#!/usr/bin/env python3
import asyncio
import ipaddress
import json
import ssl
import sys
import time
import urllib.parse
import urllib.request

HOST, PORT = "127.0.0.1", 8881
DOH_SERVERS = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"]
DOH_CTX = ssl.create_default_context(cafile="/etc/ssl/cert.pem")
TLS_PORTS = {443, 8443}

_dns_cache: dict[str, tuple[list[str], float]] = {}


def log(*parts):
    print(time.strftime("%H:%M:%S"), *parts, file=sys.stderr, flush=True)


def doh_lookup(name):
    for server in DOH_SERVERS:
        url = f"{server}?name={urllib.parse.quote(name)}&type=A"
        req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
        try:
            with urllib.request.urlopen(req, timeout=5, context=DOH_CTX) as resp:
                answers = [a for a in json.load(resp).get("Answer", []) if a.get("type") == 1]
        except Exception as e:
            log("doh error:", server, name, e)
            continue
        if answers:
            ttl = max(60, min(a.get("TTL", 300) for a in answers))
            return [a["data"] for a in answers], ttl
    return None, 0


async def resolve(name):
    try:
        ipaddress.ip_address(name)
        return [name]
    except ValueError:
        pass
    cached = _dns_cache.get(name)
    if cached and cached[1] > time.monotonic():
        return cached[0]
    ips, ttl = await asyncio.to_thread(doh_lookup, name)
    if not ips:
        return [name]
    _dns_cache[name] = (ips, time.monotonic() + ttl)
    return ips


async def open_upstream(name, port):
    last_err = None
    for ip in await resolve(name):
        try:
            return await asyncio.wait_for(asyncio.open_connection(ip, port), 10)
        except (OSError, asyncio.TimeoutError) as e:
            last_err = e
    raise OSError(f"cannot connect to {name}:{port} ({last_err})")


def split_client_hello(header, body, name):
    pos = body.find(name.encode())
    cut = pos + len(name) // 2 if pos > 0 else 1
    prefix = header[:3]
    return (prefix + cut.to_bytes(2, "big") + body[:cut]
            + prefix + (len(body) - cut).to_bytes(2, "big") + body[cut:])


async def pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
    except (OSError, asyncio.IncompleteReadError):
        writer.close()


async def handle(client_r, client_w):
    up_w = None
    try:
        head = await asyncio.wait_for(client_r.readuntil(b"\r\n\r\n"), 30)
        lines = head.decode("latin-1").split("\r\n")
        method, target, version = lines[0].split(" ", 2)

        if method == "CONNECT":
            name, _, port = target.rpartition(":")
            name, port = name.strip("[]"), int(port)
            up_r, up_w = await open_upstream(name, port)
            client_w.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client_w.drain()
            if port in TLS_PORTS:
                header = await client_r.readexactly(5)
                if header[0] == 0x16:
                    body = await client_r.readexactly(int.from_bytes(header[3:5], "big"))
                    up_w.write(split_client_hello(header, body, name))
                else:
                    up_w.write(header)
        else:
            url = urllib.parse.urlsplit(target)
            up_r, up_w = await open_upstream(url.hostname, url.port or 80)
            path = urllib.parse.urlunsplit(("", "", url.path or "/", url.query, ""))
            headers = [h for h in lines[1:] if h and not h.lower().startswith(
                ("proxy-connection:", "connection:", "keep-alive:"))]
            up_w.write("\r\n".join([f"{method} {path} {version}", *headers,
                                    "Connection: close", "", ""]).encode("latin-1"))

        await asyncio.gather(pipe(client_r, up_w), pipe(up_r, client_w))
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
        pass
    except Exception as e:
        log("error:", e)
    finally:
        for w in (client_w, up_w):
            if w:
                w.close()


async def main():
    server = await asyncio.start_server(handle, HOST, PORT)
    log(f"listening on http://{HOST}:{PORT}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
