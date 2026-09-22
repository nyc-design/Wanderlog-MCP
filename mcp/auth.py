"""Standalone, unofficial Wanderlog session-token OAuth bridge.

build_auth(app, public_url, state_dir, validate) registers every OAuth route.
The caller owns its HTTP client; validate is async, returns None on success,
and raises ValueError for an invalid session. The caller validates the supplied
connect.sid cookie value against https://wanderlog.com/api/user and owns HTTP.
Never submit Wanderlog passwords. Supported scopes are mcp and offline_access;
omitted scope defaults to mcp. Refresh tokens require offline_access consent.
Existing pre-scope grants retain their previously issued refresh capability.

Configuration: AUTH_CALLBACK_HOSTS is a comma-separated exact HTTPS hostname
allowlist (default: chatgpt.com,chat.openai.com). No wildcards, subdomain matching,
userinfo, fragments, non-default ports, or HTTP/localhost exception are allowed.
DCR registers exact redirect URI strings within that allowlist. PUBLIC_URL must
be HTTPS, without a trailing slash, query, or fragment; a path prefix is allowed.

Persist the state directory privately: auth.sqlite3 and fernet.key together are
needed across restarts. The generated encryption key is local, mode 0600 (not a
KMS); encrypted sessions are deleted on grant expiry/revocation. Token digests,
not bearer credentials, are persisted. SQLite work is short and synchronous;
this implementation targets a modest single-instance service, not a distributed
identity provider. No secrets are logged here. The caller/proxy MUST disable
query/body logging for OAuth routes (authorization codes appear in redirects).
Terminate TLS at a trusted proxy, preserve the browser Origin, and enforce an
outer request/connection limit. Forwarded client IP headers are not trusted. OAuth endpoint and invalid-bearer
limits use the socket peer and are shared behind a proxy. Valid MCP requests
instead use independent persisted per-grant limits, unaffected by invalid traffic.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
from typing import Awaitable, Callable
from urllib.parse import parse_qsl, urlencode, urlsplit

from aiohttp import web
from cryptography.fernet import Fernet, InvalidToken

Validate = Callable[[str], Awaitable[None]]
AUTH_KEY = web.AppKey("wanderlog_auth", object)
COOKIE = "__Host-wanderlog-csrf"
HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Content-Security-Policy": "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin",
    "Strict-Transport-Security": "max-age=31536000",
}


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _opaque() -> str:
    return secrets.token_urlsafe(32)


def _error(code: str = "invalid_request", status: int = 400) -> web.Response:
    return web.json_response({"error": code}, status=status)


class Auth:
    ACCESS_TTL = 3600
    GRANT_TTL = 30 * 86400
    CLIENT_TTL = 90 * 86400
    FORM_TTL = 600
    CODE_TTL = 120
    MAX_CLIENTS = 1000
    MAX_FORMS = 1000
    MAX_GRANTS = 10000
    MAX_TOKENS = 100000
    MAX_RATE_KEYS = 4096
    BODY_LIMIT = 16384
    VALIDATE_TIMEOUT = 15

    def __init__(self, public_url: str, state_dir: str | Path, validate: Validate):
        u = urlsplit(public_url)
        if (u.scheme != "https" or not u.hostname or u.username is not None
                or u.password is not None or u.query or u.fragment
                or public_url.endswith("/") or '"' in public_url
                or any(ord(c) < 33 or ord(c) > 126 for c in public_url)
                or "\\" in public_url or "/../" in u.path):
            raise ValueError("public_url must be a canonical HTTPS URL without trailing slash")
        # Accessing port also rejects malformed ports.
        if u.port not in (None, 443):
            raise ValueError("public_url must use the HTTPS default port")
        self.public_url = public_url
        self.origin = f"{u.scheme}://{u.netloc}"
        self.prefix = u.path
        self.resource = public_url + "/mcp"
        self.metadata_path = "/.well-known/oauth-protected-resource" + self.prefix + "/mcp"
        self.metadata_url = self.origin + self.metadata_path
        self.validate = validate
        hosts = os.environ.get("AUTH_CALLBACK_HOSTS", "chatgpt.com,chat.openai.com")
        self.callback_hosts = frozenset(h.strip().lower() for h in hosts.split(","))
        if not self.callback_hosts or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+", h)
            for h in self.callback_hosts
        ):
            raise ValueError("AUTH_CALLBACK_HOSTS must contain exact DNS hostnames")
        directory = Path(state_dir)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        key_path = directory / "fernet.key"
        db_path = directory / "auth.sqlite3"
        try:
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            if key_path.is_symlink() or key_path.stat().st_mode & 0o077:
                raise ValueError("fernet.key must be a private regular file (0600)")
            key = key_path.read_bytes()
        else:
            # A missing key with an existing database must fail, not silently
            # replace the key and strand all encrypted grants.
            if db_path.exists():
                os.close(fd)
                key_path.unlink()
                raise ValueError("existing auth database has no encryption key")
            key = Fernet.generate_key()
            with os.fdopen(fd, "wb") as stream:
                stream.write(key)
                stream.flush()
                os.fsync(stream.fileno())
        self.fernet = Fernet(key)
        if db_path.is_symlink():
            raise ValueError("auth database cannot be a symlink")
        fd = os.open(db_path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        os.chmod(db_path, 0o600)
        self.db = sqlite3.connect(db_path, timeout=2)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA secure_delete=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS clients (
                id TEXT PRIMARY KEY, redirects TEXT NOT NULL, expires REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS forms (
                id TEXT PRIMARY KEY, cookie TEXT NOT NULL, params TEXT NOT NULL,
                expires REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS grants (
                id TEXT PRIMARY KEY, client TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
                session BLOB NOT NULL, expires REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS codes (
                digest TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
                redirect TEXT NOT NULL, challenge TEXT NOT NULL, expires REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS tokens (
                digest TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
                kind TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, expires REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS rates (
                key TEXT PRIMARY KEY, start REAL NOT NULL, count INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS token_grant ON tokens(grant_id);
            CREATE INDEX IF NOT EXISTS code_grant ON codes(grant_id);
        """)
        if "scope" not in {row[1] for row in self.db.execute("PRAGMA table_info(grants)")}:
            with self.db:
                # Old grants already consented to persistent access and refresh.
                self.db.execute("ALTER TABLE grants ADD COLUMN scope TEXT NOT NULL DEFAULT 'mcp offline_access'")
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(grants)")}
        with self.db:
            if "rate_start" not in columns:
                self.db.execute("ALTER TABLE grants ADD COLUMN rate_start REAL NOT NULL DEFAULT 0")
            if "rate_count" not in columns:
                self.db.execute("ALTER TABLE grants ADD COLUMN rate_count INTEGER NOT NULL DEFAULT 0")
        existing = self.db.execute("SELECT value FROM config WHERE key='resource'").fetchone()
        if existing and existing[0] != self.resource:
            self.db.close()
            raise ValueError("persisted auth database belongs to a different public resource")
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO config VALUES ('resource', ?)", (self.resource,))
        self._prune()

    def _prune(self) -> None:
        now = time.time()
        with self.db:
            # Abandoned code flows must not retain the upstream session for a month.
            self.db.execute("""DELETE FROM grants WHERE id IN
                (SELECT grant_id FROM codes WHERE expires <= ?)
                AND NOT EXISTS (SELECT 1 FROM tokens WHERE grant_id=grants.id)""", (now,))
            for table in ("clients", "forms", "codes", "tokens", "grants"):
                self.db.execute(f"DELETE FROM {table} WHERE expires <= ?", (now,))
            self.db.execute("DELETE FROM rates WHERE start <= ?", (now - 60,))

    def _capacity(self, table: str, maximum: int) -> bool:
        return self.db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] < maximum

    def _rate(self, request: web.Request, group: str, limit: int) -> bool:
        self._prune()
        now = time.time()
        keys = ((group + ":global", limit * 10),
                (group + ":" + _digest(request.remote or "unknown"), limit))
        with self.db:
            for key, maximum in keys:
                row = self.db.execute("SELECT count FROM rates WHERE key=?", (key,)).fetchone()
                if row and row[0] >= maximum:
                    return False
                if not row and not self._capacity("rates", self.MAX_RATE_KEYS):
                    return False
            for key, _ in keys:
                self.db.execute("INSERT INTO rates VALUES (?, ?, 1) ON CONFLICT(key) DO UPDATE SET count=count+1", (key, now))
        return True

    def _redirect_ok(self, uri: object) -> bool:
        if not isinstance(uri, str) or len(uri) > 2048 or not uri.isascii():
            return False
        if any(ord(c) < 33 for c in uri) or "\\" in uri or "#" in uri:
            return False
        try:
            u = urlsplit(uri)
            return (u.scheme == "https" and u.hostname in self.callback_hosts
                    and u.username is None and u.password is None
                    and u.port in (None, 443) and not u.fragment)
        except ValueError:
            return False

    def _origin_ok(self, request: web.Request, required: bool = False) -> bool:
        origin = request.headers.get("Origin")
        if not origin:
            return not required
        return origin == self.origin

    async def _body(self, request: web.Request, *, json_body: bool = False) -> dict:
        expected = "application/json" if json_body else "application/x-www-form-urlencoded"
        if request.content_type != expected:
            raise ValueError("content type")
        data = bytearray()
        async with asyncio.timeout(10):
            async for chunk in request.content.iter_chunked(4096):
                data.extend(chunk)
                if len(data) > self.BODY_LIMIT:
                    raise ValueError("body too large")
        if json_body:
            def unique(pairs):
                result = {}
                for k, v in pairs:
                    if k in result:
                        raise ValueError("duplicate key")
                    result[k] = v
                return result
            result = json.loads(data.decode("utf-8"), object_pairs_hook=unique)
            if not isinstance(result, dict):
                raise ValueError("object required")
            return result
        pairs = parse_qsl(data.decode("utf-8"), keep_blank_values=True, max_num_fields=20)
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError("duplicate parameter")
        return result

    def _client(self, client_id: object):
        if not isinstance(client_id, str) or len(client_id) > 128:
            return None
        return self.db.execute("SELECT * FROM clients WHERE id=? AND expires>?", (client_id, time.time())).fetchone()

    async def resource_metadata(self, request):
        return web.json_response({"resource": self.resource, "authorization_servers": [self.public_url],
                                  "scopes_supported": ["mcp", "offline_access"], "bearer_methods_supported": ["header"]})

    async def server_metadata(self, request):
        return web.json_response({
            "issuer": self.public_url,
            "authorization_response_iss_parameter_supported": True,
            "scopes_supported": ["mcp", "offline_access"],
            "authorization_endpoint": self.public_url + "/authorize",
            "token_endpoint": self.public_url + "/token",
            "registration_endpoint": self.public_url + "/register",
            "revocation_endpoint": self.public_url + "/revoke",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"],
        })

    async def register(self, request):
        if not self._rate(request, "register", 10):
            return _error("temporarily_unavailable", 429)
        data = await self._body(request, json_body=True)
        redirects = data.get("redirect_uris")
        if (not isinstance(redirects, list) or not 1 <= len(redirects) <= 5
                or not all(self._redirect_ok(uri) for uri in redirects)):
            return _error("invalid_redirect_uri")
        grant_types = data.get("grant_types", ["authorization_code", "refresh_token"])
        if (data.get("token_endpoint_auth_method", "none") != "none"
                or not isinstance(grant_types, list)
                or not all(isinstance(g, str) for g in grant_types)
                or "authorization_code" not in grant_types
                or any(g not in ("authorization_code", "refresh_token") for g in grant_types)
                or data.get("response_types", ["code"]) != ["code"]
                or any(k in data for k in ("client_secret", "jwks", "jwks_uri", "request_uris"))):
            return _error("invalid_client_metadata")
        if not self._capacity("clients", self.MAX_CLIENTS):
            return _error("temporarily_unavailable", 503)
        client_id = _opaque()
        with self.db:
            self.db.execute("INSERT INTO clients VALUES (?, ?, ?)", (client_id, json.dumps(redirects), time.time() + self.CLIENT_TTL))
        return web.json_response({"client_id": client_id, "client_id_issued_at": int(time.time()),
            "redirect_uris": redirects, "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"]}, status=201)

    async def authorize_get(self, request):
        if not self._rate(request, "authorize", 30):
            return _error("temporarily_unavailable", 429)
        if len(request.query_string) > 8192 or len(request.query) != len(set(request.query)):
            return _error()
        p = dict(request.query)
        client = self._client(p.get("client_id"))
        if not client or p.get("redirect_uri") not in json.loads(client["redirects"]):
            return _error()
        if (not self._redirect_ok(p["redirect_uri"]) or p.get("response_type") != "code"
                or p.get("resource") != self.resource or p.get("code_challenge_method") != "S256"
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", p.get("code_challenge", ""))
                or len(p.get("state", "")) > 1024):
            return _error()
        scopes = p.get("scope", "mcp").split(" ")
        if not scopes or any(scope not in ("mcp", "offline_access") for scope in scopes):
            return _error("invalid_scope")
        p["scope"] = " ".join(scope for scope in ("mcp", "offline_access") if scope in scopes)
        if not self._capacity("forms", self.MAX_FORMS):
            return _error("temporarily_unavailable", 503)
        nonce, cookie = _opaque(), _opaque()
        with self.db:
            self.db.execute("INSERT INTO forms VALUES (?, ?, ?, ?)",
                            (_digest(nonce), _digest(cookie), json.dumps(p), time.time() + self.FORM_TTL))
        body = f'''<!doctype html><html lang="en"><meta charset="utf-8">
<title>Unofficial Wanderlog connector</title><h1>Unofficial Wanderlog connector</h1>
<p>This service is not affiliated with or endorsed by Wanderlog. Connect only if you trust this server.</p>
<p>Paste your Wanderlog session token, never your password. It will be encrypted on this server.
This connector initially exposes read-only access. However, the session cookie itself may allow
account edits: only connect if you trust the server operator with that broader access.
The connected client can access your Wanderlog account through this connector until revoked or expired.</p>
<ol><li>Sign in to Wanderlog in your browser at <code>https://wanderlog.com</code>.</li>
<li>Open browser Developer Tools, then <strong>Application</strong> (or <strong>Storage</strong>).</li>
<li>Under <strong>Cookies</strong>, select <code>https://wanderlog.com</code>.</li>
<li>Find <code>connect.sid</code> and copy only its <strong>VALUE</strong>, not the cookie name,
not a full Cookie header, and never your password. Paste that value below.</li></ol>
<p>Requested permissions: <code>{html.escape(p['scope'])}</code>.
Offline access allows this client to renew access without reconnecting.</p>
<p>Client: <code>{html.escape(p['client_id'])}</code><br>Callback: <code>{html.escape(p['redirect_uri'])}</code></p>
<form method="post" action="{html.escape(self.prefix + '/authorize', quote=True)}">
<input type="hidden" name="csrf" value="{nonce}">
<label>Wanderlog session token <input type="password" name="session_token" required maxlength="4096" autocomplete="off"></label>
<button type="submit">Connect account</button></form></html>'''
        response = web.Response(text=body, content_type="text/html")
        response.set_cookie(COOKIE, cookie, max_age=self.FORM_TTL, secure=True, httponly=True, samesite="Lax", path="/")
        return response

    async def authorize_post(self, request):
        if not self._origin_ok(request, required=True):
            return web.json_response({"error": "access_denied", "error_description": "Connection form expired or browser verification failed. Start Connect again from ChatGPT and allow cookies for this site."}, status=403)
        if not self._rate(request, "validate", 10):
            return _error("temporarily_unavailable", 429)
        p = await self._body(request)
        nonce, cookie = p.get("csrf", ""), request.cookies.get(COOKIE, "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", nonce) or len(cookie) != 43:
            return web.json_response({"error": "access_denied", "error_description": "Connection form expired or browser verification failed. Start Connect again from ChatGPT and allow cookies for this site."}, status=403)
        # Consume before awaiting the remote validator, preventing concurrent replay.
        with self.db:
            row = self.db.execute("SELECT * FROM forms WHERE id=?", (_digest(nonce),)).fetchone()
            if not row or not hmac.compare_digest(row["cookie"], _digest(cookie)):
                return web.json_response({"error": "access_denied", "error_description": "Connection form expired or browser verification failed. Start Connect again from ChatGPT and allow cookies for this site."}, status=403)
            self.db.execute("DELETE FROM forms WHERE id=?", (_digest(nonce),))
        if row["expires"] <= time.time():
            return web.json_response({"error": "access_denied", "error_description": "Connection form expired or browser verification failed. Start Connect again from ChatGPT and allow cookies for this site."}, status=403)
        token = p.get("session_token", "")
        if not 1 <= len(token) <= 4096 or any(ord(c) < 33 or ord(c) > 126 for c in token):
            return web.json_response({"error": "access_denied", "error_description": "Wanderlog session could not be validated. Start Connect again and paste only the current connect.sid cookie VALUE from a signed-in Wanderlog browser session, not the cookie name or a full Cookie header."}, status=400)
        try:
            async with asyncio.timeout(self.VALIDATE_TIMEOUT):
                result = await self.validate(token)
            if result is not None:
                return _error("temporarily_unavailable", 502)
        except ValueError:
            return web.json_response({"error": "access_denied", "error_description": "Wanderlog session could not be validated. Start Connect again and paste only the current connect.sid cookie VALUE from a signed-in Wanderlog browser session, not the cookie name or a full Cookie header."}, status=400)
        except Exception:
            # Upstream exceptions may include credentials: never render/log them.
            return _error("temporarily_unavailable", 502)
        params = json.loads(row["params"])
        client = self._client(params["client_id"])
        if not client or not self._capacity("grants", self.MAX_GRANTS):
            return _error("temporarily_unavailable", 503)
        grant_id, code = _opaque(), _opaque()
        with self.db:
            if not self._capacity("grants", self.MAX_GRANTS):
                return _error("temporarily_unavailable", 503)
            self.db.execute("INSERT INTO grants (id, client, session, expires, scope) VALUES (?, ?, ?, ?, ?)",
                (grant_id, params["client_id"], self.fernet.encrypt(token.encode()),
                 min(time.time() + (self.GRANT_TTL if "offline_access" in params.get("scope", "mcp").split() else self.ACCESS_TTL), client["expires"]),
                 params.get("scope", "mcp")))
            self.db.execute("INSERT INTO codes VALUES (?, ?, ?, ?, ?)",
                (_digest(code), grant_id, params["redirect_uri"], params["code_challenge"], time.time() + self.CODE_TTL))
        query = {"code": code, "iss": self.public_url}
        if "state" in params:
            query["state"] = params["state"]
        separator = "&" if "?" in params["redirect_uri"] else "?"
        response = web.Response(status=303, headers={"Location": params["redirect_uri"] + separator + urlencode(query)})
        response.del_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="Lax")
        return response

    def _issue(self, grant, scope=None):
        access, refresh = _opaque(), _opaque()
        now = time.time()
        expiry = min(now + self.ACCESS_TTL, grant["expires"])
        rows = [(_digest(access), grant["id"], "access", expiry)]
        result = {"access_token": access, "token_type": "Bearer", "expires_in": int(expiry - now),
                  "scope": grant["scope"] if scope is None else scope}
        if "offline_access" in grant["scope"].split():
            rows.append((_digest(refresh), grant["id"], "refresh", grant["expires"]))
            result["refresh_token"] = refresh
        self.db.executemany("INSERT INTO tokens VALUES (?, ?, ?, 0, ?)", rows)
        return web.json_response(result)

    async def token(self, request):
        if not self._rate(request, "token", 60):
            return _error("temporarily_unavailable", 429)
        p = await self._body(request)
        if "Authorization" in request.headers or "client_secret" in p or not self._client(p.get("client_id")):
            return _error("invalid_client", 401)
        if p.get("resource") != self.resource:
            return _error("invalid_target")
        if not self._capacity("tokens", self.MAX_TOKENS - 1):
            return _error("temporarily_unavailable", 503)
        kind = p.get("grant_type")
        requested_scope = None
        now = time.time()
        # No await inside transactions: single-use checks and issuance are atomic.
        with self.db:
            if kind == "authorization_code":
                code = self.db.execute("SELECT * FROM codes WHERE digest=?", (_digest(p.get("code", "")),)).fetchone()
                if not code:
                    return _error("invalid_grant")
                grant = self.db.execute("SELECT * FROM grants WHERE id=?", (code["grant_id"],)).fetchone()
                verifier = p.get("code_verifier", "")
                if (not grant or grant["client"] != p["client_id"] or grant["expires"] <= now
                        or code["expires"] <= now or code["redirect"] != p.get("redirect_uri")
                        or not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier)):
                    return _error("invalid_grant")
                challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
                if not hmac.compare_digest(challenge, code["challenge"]):
                    return _error("invalid_grant")
                if "scope" in p and set(p["scope"].split(" ")) != set(grant["scope"].split()):
                    return _error("invalid_scope")
                self.db.execute("DELETE FROM codes WHERE digest=?", (code["digest"],))
            elif kind == "refresh_token":
                old = self.db.execute("SELECT * FROM tokens WHERE digest=? AND kind='refresh'", (_digest(p.get("refresh_token", "")),)).fetchone()
                if not old:
                    return _error("invalid_grant")
                grant = self.db.execute("SELECT * FROM grants WHERE id=?", (old["grant_id"],)).fetchone()
                if not grant or grant["client"] != p["client_id"] or grant["expires"] <= now or old["expires"] <= now:
                    return _error("invalid_grant")
                if old["used"]:
                    self.db.execute("DELETE FROM grants WHERE id=?", (grant["id"],))
                    return _error("invalid_grant")
                if "scope" in p:
                    scopes = set(p["scope"].split(" "))
                    if not scopes or not scopes <= set(grant["scope"].split()):
                        return _error("invalid_scope")
                    requested_scope = " ".join(s for s in ("mcp", "offline_access") if s in scopes)
                self.db.execute("UPDATE tokens SET used=1 WHERE digest=?", (old["digest"],))
            else:
                return _error("unsupported_grant_type")
            return self._issue(grant, requested_scope)

    async def revoke(self, request):
        if not self._rate(request, "revoke", 60):
            return _error("temporarily_unavailable", 429)
        p = await self._body(request)
        if "Authorization" in request.headers or "client_secret" in p or not self._client(p.get("client_id")):
            return _error("invalid_client", 401)
        if not p.get("token"):
            return _error()
        with self.db:
            self.db.execute("DELETE FROM grants WHERE client=? AND id IN (SELECT grant_id FROM tokens WHERE digest=?)",
                            (p["client_id"], _digest(p["token"])))
        return web.Response(status=200)

    def _unauthorized(self, request):
        headers = {**HEADERS, "WWW-Authenticate":
                   f'Bearer resource_metadata="{self.metadata_url}"'}
        if not self._rate(request, "invalid_authenticate", 600):
            raise web.HTTPTooManyRequests(headers={**headers, "Retry-After": "60"})
        raise web.HTTPUnauthorized(headers=headers)

    async def authenticate(self, request: web.Request) -> dict:
        if not self._origin_ok(request):
            self._unauthorized(request)
        values = request.headers.getall("Authorization", [])
        if len(values) != 1:
            self._unauthorized(request)
        match = re.fullmatch(r"(?i:Bearer) ([A-Za-z0-9_-]{43})", values[0])
        if not match:
            self._unauthorized(request)
        row = self.db.execute("""SELECT grants.id, grants.session FROM tokens
            JOIN grants ON grants.id=tokens.grant_id JOIN clients ON clients.id=grants.client
            WHERE tokens.digest=? AND tokens.kind='access' AND tokens.used=0
            AND tokens.expires>? AND grants.expires>? AND clients.expires>?""",
            (_digest(match[1]), time.time(), time.time(), time.time())).fetchone()
        if not row:
            self._unauthorized(request)
        # These counters live on grants, not the attacker-fillable peer-rate table.
        # Access-token rotation and shared proxies cannot reset or share a quota.
        now = time.time()
        with self.db:
            updated = self.db.execute("""UPDATE grants SET
                rate_count=CASE WHEN rate_start<=? THEN 1 ELSE rate_count+1 END,
                rate_start=CASE WHEN rate_start<=? THEN ? ELSE rate_start END
                WHERE id=? AND (rate_start<=? OR rate_count<600)""",
                (now - 60, now - 60, now, row["id"], now - 60))
            if not updated.rowcount:
                raise web.HTTPTooManyRequests(headers={**HEADERS, "Retry-After": "60"})
        try:
            session = self.fernet.decrypt(row["session"]).decode()
        except (InvalidToken, UnicodeError):
            with self.db:
                self.db.execute("DELETE FROM grants WHERE id=?", (row["id"],))
            self._unauthorized(request)
        return {"id": row["id"], "session_token": session}

    async def start(self, app):
        async def expire():
            while True:
                await asyncio.sleep(60)
                try:
                    self._prune()
                except sqlite3.OperationalError:
                    # Retry on the next tick if another process holds the lock.
                    pass
        self._expiry_task = asyncio.create_task(expire())

    async def close(self, app):
        task = getattr(self, "_expiry_task", None)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self.db.close()


def build_auth(app: web.Application, public_url: str, state_dir: str | Path, validate: Validate) -> Auth:
    """Install OAuth/discovery routes and cleanup; returns the MCP authenticator."""
    auth = Auth(public_url, state_dir, validate)
    # Browsers can apply form-action to the 303 callback destination as well
    # as the initial POST. Only configured, validated callback hosts qualify.
    security_headers = dict(HEADERS)
    destinations = " ".join("https://" + host for host in sorted(auth.callback_hosts))
    security_headers["Content-Security-Policy"] = HEADERS["Content-Security-Policy"].replace(
        "form-action 'self'", "form-action 'self' " + destinations)

    @web.middleware
    async def security(request, handler):
        # Leave application/MCP errors to the caller's error boundary.
        if getattr(request.match_info.handler, "__self__", None) is not auth:
            return await handler(request)
        try:
            if request.method not in ("GET", "HEAD", "OPTIONS") and not auth._origin_ok(request):
                response = _error("access_denied", 403)
            else:
                response = await handler(request)
        except (ValueError, UnicodeError, TimeoutError):
            response = _error()
        except sqlite3.OperationalError:
            response = _error("temporarily_unavailable", 503)
        except web.HTTPException as exc:
            exc.headers.update(security_headers)
            raise
        response.headers.update(security_headers)
        return response

    app.middlewares.append(security)
    app[AUTH_KEY] = auth
    app.on_startup.append(auth.start)
    app.on_cleanup.append(auth.close)
    resource_paths = {"/.well-known/oauth-protected-resource", auth.metadata_path}
    server_paths = {"/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server" + auth.prefix}
    for path in sorted(resource_paths):
        app.router.add_get(path, auth.resource_metadata)
    for path in sorted(server_paths):
        app.router.add_get(path, auth.server_metadata)
    app.router.add_post(auth.prefix + "/register", auth.register)
    app.router.add_get(auth.prefix + "/authorize", auth.authorize_get)
    app.router.add_post(auth.prefix + "/authorize", auth.authorize_post)
    app.router.add_post(auth.prefix + "/token", auth.token)
    app.router.add_post(auth.prefix + "/revoke", auth.revoke)
    return auth
