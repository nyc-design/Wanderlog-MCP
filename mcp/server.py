"""Authenticated, stateless MCP bridge to isolated Wanderlog CLI processes."""
import asyncio
import contextlib
import json
import os
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

import aiohttp
from aiohttp import web
from auth import build_auth

# Explicit allowlist: upstream also exposes account/configuration tools which must
# never be reachable merely because a future upstream release adds them.
TOOLS = frozenset({"list_trips", "get_trip", "get_trip_plan", "get_itinerary",
                   "list_places", "list_sections", "get_flights", "get_trip_sections"})
PROTOCOL = "2025-06-18"
SUPPORTED = {PROTOCOL, "2025-11-25"}
MAX_OUTPUT = 8 * 1024 * 1024
HTTP_CLIENT = web.AppKey("upstream_http", aiohttp.ClientSession)


async def cli_rpc(token, method, params, binary="/usr/local/bin/wanderlog"):
    """One process and temporary HOME per request; no cross-account state."""
    with tempfile.TemporaryDirectory(prefix="wanderlog-mcp-") as home:
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": home,
               "XDG_CONFIG_HOME": home + "/config", "XDG_CACHE_HOME": home + "/cache",
               "XDG_DATA_HOME": home + "/data", "WANDERLOG_DISABLE_KEYCHAIN": "1",
               "WANDERLOG_AUTH_SESSION_COOKIE": token}
        proc = await asyncio.create_subprocess_exec(
            binary, "mcp", env=env, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            limit=MAX_OUTPUT)
        async def send(message):
            proc.stdin.write(json.dumps(message).encode() + b"\n")
            await proc.stdin.drain()
        output_bytes = 0
        async def receive(expected):
            nonlocal output_bytes
            for _ in range(16):
                line = await proc.stdout.readline()
                output_bytes += len(line)
                if output_bytes > MAX_OUTPUT:
                    raise RuntimeError("Upstream output limit exceeded")
                if not line:
                    raise RuntimeError("Upstream process closed")
                message = json.loads(line)
                if not isinstance(message, dict):
                    raise RuntimeError("Invalid upstream message")
                if message.get("id") == expected:
                    return message
            raise RuntimeError("Too many upstream notifications")
        try:
            async with asyncio.timeout(45):
                await send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                    "protocolVersion": PROTOCOL, "capabilities": {},
                    "clientInfo": {"name": "wanderlog-gateway", "version": "0.1.0"}}})
                init = await receive(1)
                if "error" in init:
                    raise RuntimeError("Upstream initialization failed")
                await send({"jsonrpc": "2.0", "method": "notifications/initialized"})
                await send({"jsonrpc": "2.0", "id": 2, "method": method, "params": params})
                return await receive(2)
        finally:
            if proc.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), 3)
                except TimeoutError:
                    with contextlib.suppress(ProcessLookupError):
                        proc.kill()
                    await proc.wait()


async def validate_session(client, token):
    # Accept only a cookie VALUE, not an arbitrary Cookie header.
    if not isinstance(token, str) or not 8 <= len(token) <= 4096 or any(
            ord(c) <= 32 or ord(c) >= 127 or c in ';,\"\\' for c in token):
        raise ValueError("Invalid session token")
    try:
        async with client.get("https://wanderlog.com/api/user",
                              headers={"Cookie": "connect.sid=" + token,
                                       "User-Agent": "wanderlog-mcp/0.1"},
                              allow_redirects=False) as response:
            if response.status != 200:
                raise ValueError("Session could not be validated")
            raw = bytearray()
            async for chunk in response.content.iter_chunked(8192):
                raw.extend(chunk)
                if len(raw) > 65536:
                    raise ValueError("Unexpected session response")
            data = json.loads(raw)
            identity = data.get("id") or (data.get("user") or {}).get("id")
            if not isinstance(identity, int) or identity <= 0:
                raise ValueError("Session could not be validated")
    except (aiohttp.ClientError, TimeoutError, TypeError, AttributeError, json.JSONDecodeError):
        raise ValueError("Session could not be validated") from None


def make_app(public_url, state_dir, runner=cli_rpc, validator=None):
    parsed = urlsplit(public_url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise ValueError("PUBLIC_URL must be an HTTPS origin, without a path")
    public_url = public_url.rstrip("/")

    @web.middleware
    async def boundaries(request, handler):
        # The canonical origin comes from operator config, never proxy headers.
        if request.host != urlsplit(public_url).netloc:
            raise web.HTTPMisdirectedRequest()
        if request.headers.get("Origin") not in (None, public_url):
            raise web.HTTPForbidden(text="Origin not allowed")
        try:
            response = await handler(request)
        except web.HTTPException as exc:
            response = web.Response(status=exc.status, headers=exc.headers, text=exc.text)
        except Exception:
            # Avoid logging request bodies, headers or exception values.
            response = web.Response(status=500, text="Request failed")
        response.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                                 "Referrer-Policy": "strict-origin",
                                 "Content-Security-Policy": "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"})
        return response

    app = web.Application(client_max_size=16384, middlewares=[boundaries])
    async def lifetime(app):
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15),
                                         cookie_jar=aiohttp.DummyCookieJar()) as client:
            app[HTTP_CLIENT] = client
            yield
    app.cleanup_ctx.append(lifetime)
    async def validate(token):
        await validate_session(app[HTTP_CLIENT], token)
    auth = build_auth(app, public_url, state_dir, validator or validate)
    semaphore = asyncio.Semaphore(8)
    body_slots = asyncio.Semaphore(32)

    def error(request_id, code, message):
        return web.json_response({"jsonrpc": "2.0", "id": request_id,
                                  "error": {"code": code, "message": message}})

    async def mcp(request):
        identity = await auth.authenticate(request)
        if request.method != "POST":
            raise web.HTTPMethodNotAllowed(request.method, ["POST"])
        if request.content_type != "application/json":
            raise web.HTTPUnsupportedMediaType()
        if request.headers.get("MCP-Protocol-Version", PROTOCOL) not in SUPPORTED:
            raise web.HTTPBadRequest(text="Unsupported protocol version")
        accept = request.headers.get("Accept", "")
        if "application/json" not in accept or "text/event-stream" not in accept:
            raise web.HTTPNotAcceptable(text="Accept application/json and text/event-stream")
        def reject_constant(value):
            raise ValueError("Invalid JSON constant")
        if body_slots.locked():
            raise web.HTTPServiceUnavailable(headers={"Retry-After": "5"})
        try:
            async with body_slots, asyncio.timeout(10):
                body = json.loads(await request.text(), parse_constant=reject_constant)
        except (ValueError, UnicodeError, RecursionError):
            return error(None, -32700, "Parse error")
        except TimeoutError:
            raise web.HTTPRequestTimeout() from None
        if not isinstance(body, dict):
            return error(None, -32600, "Invalid request")
        request_id = body.get("id")
        method = body.get("method")
        params = body.get("params", {})
        if (body.get("jsonrpc") != "2.0" or not isinstance(method, str)
                or not isinstance(params, dict)
                or ("id" in body and (isinstance(request_id, bool)
                                      or not isinstance(request_id, (str, int))))):
            return error(None, -32600, "Invalid request")
        if "id" not in body:
            if method == "notifications/initialized":
                return web.Response(status=202)
            raise web.HTTPBadRequest(text="Unsupported notification")
        if method == "initialize":
            requested = params.get("protocolVersion")
            result = {"protocolVersion": requested if isinstance(requested, str) and requested in SUPPORTED else PROTOCOL,
                      "capabilities": {"tools": {}},
                      "serverInfo": {"name": "wanderlog-mcp", "version": "0.1.0"},
                      "instructions": "Read-only Wanderlog access for the connected account."}
        elif method == "ping":
            result = {}
        elif method in ("tools/list", "tools/call"):
            if method == "tools/call" and (not isinstance(params.get("name"), str)
                                            or params["name"] not in TOOLS):
                return error(request_id, -32602, "Tool not available")
            if method == "tools/call" and not isinstance(params.get("arguments", {}), dict):
                return error(request_id, -32602, "Arguments must be an object")
            if method == "tools/list" and "cursor" in params:
                return error(request_id, -32602, "Pagination not supported")
            if semaphore.locked():
                raise web.HTTPServiceUnavailable(headers={"Retry-After": "5"})
            try:
                async with semaphore:
                    upstream = await runner(identity["session_token"], method, params)
                if "error" in upstream:
                    return error(request_id, -32603, "Wanderlog request failed")
                result = upstream["result"]
                if method == "tools/list":
                    result = {"tools": [dict(tool, securitySchemes=[{"type": "oauth2", "scopes": ["mcp"]}],
                             annotations={"readOnlyHint": True,
                             "destructiveHint": False, "openWorldHint": True})
                             for tool in result["tools"] if tool["name"] in TOOLS]}
                elif result.get("isError"):
                    # Upstream error strings can embed raw API responses.
                    result = {"isError": True, "content": [{"type": "text", "text":
                              "Wanderlog request failed. Check arguments or reconnect your account."}]}
            except (TimeoutError, OSError, RuntimeError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
                return error(request_id, -32603, "Wanderlog request failed")
        else:
            return error(request_id, -32601, "Method not found")
        return web.json_response({"jsonrpc": "2.0", "id": request_id, "result": result})

    async def health(request):
        return web.json_response({"status": "ok"})
    app.router.add_route("*", "/mcp", mcp)
    app.router.add_get("/healthz", health)
    return app


if __name__ == "__main__":
    os.umask(0o077)
    public_url = os.environ.get("PUBLIC_URL", "")
    if not public_url:
        raise SystemExit("Set PUBLIC_URL to your Coder public HTTPS origin before starting.")
    app = make_app(public_url, Path(os.environ.get("STATE_DIR", str(
        Path.home() / ".local/share/wanderlog-mcp"))))
    web.run_app(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")),
                access_log=None, print=None)
