"""Run: python -m unittest discover -s mcp -p test_auth.py -v."""

import asyncio
import base64
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

# Works both as a standalone unittest file and inside a package named mcp.
_spec = importlib.util.spec_from_file_location("wanderlog_auth_under_test", Path(__file__).with_name("auth.py"))
auth_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(auth_module)
build_auth = auth_module.build_auth
COOKIE = auth_module.COOKIE

PUBLIC = "https://connector.example"
REDIRECT = "https://chatgpt.com/connector/callback"
SESSION = "sensitive-wanderlog-session-token"
VERIFIER = "a" * 64
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode()


class AuthTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.calls = []

        async def validate(token):
            self.calls.append(token)
            if token != SESSION:
                raise ValueError("secret should never appear: " + token)

        self.validator = validate
        self.env = patch.dict(os.environ, {"AUTH_CALLBACK_HOSTS": "chatgpt.com,chat.openai.com"})
        self.env.start()
        await self.start()

    async def start(self, public=PUBLIC):
        self.app = web.Application()
        self.auth = build_auth(self.app, public, self.directory.name, self.validator)

        async def mcp(request):
            return web.json_response(await self.auth.authenticate(request))

        self.app.router.add_post(self.auth.prefix + "/mcp", mcp)
        self.client = TestClient(TestServer(self.app))
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()
        self.env.stop()
        self.directory.cleanup()

    async def register(self, redirects=None, **extra):
        response = await self.client.post(self.auth.prefix + "/register", json={
            "redirect_uris": redirects or [REDIRECT], **extra})
        self.assertEqual(response.status, 201, await response.text())
        return (await response.json())["client_id"]

    def params(self, client_id, **extra):
        return {"client_id": client_id, "redirect_uri": REDIRECT,
                "response_type": "code", "code_challenge": CHALLENGE,
                "code_challenge_method": "S256", "resource": self.auth.resource,
                "state": "opaque-state", "scope": "mcp offline_access", **extra}

    async def form(self, client_id, **extra):
        response = await self.client.get(self.auth.prefix + "/authorize", params=self.params(client_id, **extra))
        self.assertEqual(response.status, 200, await response.text())
        text = await response.text()
        self.assertIn("Unofficial", text)
        self.assertIn("never your password", text)
        csrf = re.search(r'name="csrf" value="([^"]+)"', text).group(1)
        cookie = response.cookies[COOKIE]
        self.assertTrue(cookie["secure"])
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"], "Lax")
        return {"csrf": csrf, "session_token": SESSION}, {
            "Cookie": COOKIE + "=" + cookie.value, "Origin": PUBLIC}

    async def code(self, client_id):
        data, headers = await self.form(client_id)
        response = await self.client.post("/authorize", data=data, headers=headers, allow_redirects=False)
        self.assertEqual(response.status, 303, await response.text())
        query = parse_qs(urlsplit(response.headers["Location"]).query)
        self.assertEqual(query["state"], ["opaque-state"])
        self.assertEqual(query["iss"], [PUBLIC])
        return query["code"][0]

    async def exchange(self, client_id, code, **extra):
        return await self.client.post("/token", data={"grant_type": "authorization_code",
            "client_id": client_id, "code": code, "redirect_uri": REDIRECT,
            "code_verifier": VERIFIER, "resource": self.auth.resource, **extra})

    async def tokens(self):
        client_id = await self.register()
        code = await self.code(client_id)
        response = await self.exchange(client_id, code)
        self.assertEqual(response.status, 200, await response.text())
        return client_id, await response.json()

    async def access(self, token):
        return await self.client.post("/mcp", headers={"Authorization": "Bearer " + token})

    async def refresh(self, client_id, token, **extra):
        return await self.client.post("/token", data={"grant_type": "refresh_token", "client_id": client_id,
            "refresh_token": token, "resource": self.auth.resource, **extra})

    async def test_discovery_and_unauthorized_challenge(self):
        for path in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"):
            response = await self.client.get(path)
            self.assertEqual((await response.json())["resource"], PUBLIC + "/mcp")
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            self.assertIn("form-action 'self'", response.headers["Content-Security-Policy"])
            self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        response = await self.client.get("/.well-known/oauth-authorization-server")
        metadata = await response.json()
        self.assertEqual(metadata["code_challenge_methods_supported"], ["S256"])
        self.assertIs(metadata["authorization_response_iss_parameter_supported"], True)
        self.assertEqual(metadata["scopes_supported"], ["mcp", "offline_access"])
        response = await self.client.post("/mcp")
        self.assertEqual(response.status, 401)
        self.assertEqual(response.headers["WWW-Authenticate"],
            'Bearer resource_metadata="https://connector.example/.well-known/oauth-protected-resource/mcp"')

    async def test_full_flow_encryption_and_restart(self):
        _, tokens = await self.tokens()
        response = await self.access(tokens["access_token"])
        self.assertEqual(response.status, 200)
        identity = await response.json()
        self.assertEqual(identity["session_token"], SESSION)
        self.assertEqual(set(identity), {"id", "session_token"})
        self.assertEqual(self.calls, [SESSION])
        self.assertEqual((await self.access(tokens["refresh_token"])).status, 401)
        key = Path(self.directory.name, "fernet.key")
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertEqual(Path(self.directory.name, "auth.sqlite3").stat().st_mode & 0o777, 0o600)
        for path in Path(self.directory.name).iterdir():
            data = path.read_bytes()
            for secret in (SESSION, tokens["access_token"], tokens["refresh_token"]):
                self.assertNotIn(secret.encode(), data)
        old_key = key.read_bytes()
        await self.client.close()
        await self.start()
        self.assertEqual(key.read_bytes(), old_key)
        response = await self.access(tokens["access_token"])
        self.assertEqual(await response.json(), identity)

    async def test_redirect_policy(self):
        bad = ["http://chatgpt.com/cb", "http://localhost/cb", "https://chatgpt.com.evil.test/cb",
               "https://evil.chatgpt.com/cb", "https://user@chatgpt.com/cb", "https://chatgpt.com/cb#",
               "https://chatgpt.com/cb#fragment", "https://chatgpt.com:8443/cb", "https://chatgpt.com\\@evil.test/cb"]
        for redirect in bad:
            with self.subTest(redirect=redirect):
                response = await self.client.post("/register", json={"redirect_uris": [redirect]})
                self.assertEqual(response.status, 400)
        self.assertTrue(self.auth._redirect_ok("https://chat.openai.com/callback"))
        self.assertFalse(self.auth._redirect_ok("https://chat.openai.com./callback"))

    async def test_dcr_accepts_grant_order_and_authorization_code_subset(self):
        for grants in (["authorization_code"], ["refresh_token", "authorization_code"],
                       ["authorization_code", "refresh_token"]):
            response = await self.client.post("/register", json={"redirect_uris": [REDIRECT],
                                                                     "grant_types": grants})
            self.assertEqual(response.status, 201, await response.text())
        for grants in ([], ["refresh_token"], ["authorization_code", "password"], "authorization_code", [42]):
            response = await self.client.post("/register", json={"redirect_uris": [REDIRECT],
                                                                     "grant_types": grants})
            self.assertEqual(response.status, 400)

    async def test_connection_instructions_and_session_size_limit(self):
        client_id = await self.register()
        response = await self.client.get("/authorize", params=self.params(client_id))
        text = await response.text()
        for expected in ("Application", "Storage", "Cookies", "connect.sid", "VALUE",
                         "read-only", "account edits", "server operator", 'maxlength="4096"'):
            self.assertIn(expected, text)
        data, headers = await self.form(client_id)
        data["session_token"] = "x" * 4097
        response = await self.client.post("/authorize", data=data, headers=headers, allow_redirects=False)
        self.assertEqual(response.status, 400)
        self.assertEqual(self.calls, [])
        data, headers = await self.form(client_id)
        data["session_token"] = "x" * 4096
        response = await self.client.post("/authorize", data=data, headers=headers, allow_redirects=False)
        self.assertEqual(response.status, 400)  # Reaches validator, which rejects this test value.
        self.assertEqual(self.calls, ["x" * 4096])

    async def test_public_clients_only(self):
        response = await self.client.post("/register", json={"redirect_uris": [REDIRECT],
                                                                          "token_endpoint_auth_method": "client_secret_basic"})
        self.assertEqual(response.status, 400)
        client_id = await self.register()
        code = await self.code(client_id)
        response = await self.exchange(client_id, code, client_secret="secret")
        self.assertEqual(response.status, 401)

    async def test_pkce_resource_and_exact_redirect_enforced(self):
        client_id = await self.register()
        for extra in ({"resource": PUBLIC + "/other"}, {"code_challenge_method": "plain"},
                      {"code_challenge": "short"}, {"redirect_uri": REDIRECT + "/"}, {"scope": "all"}):
            response = await self.client.get("/authorize", params=self.params(client_id, **extra))
            self.assertEqual(response.status, 400, str(extra))
            self.assertNotIn("Location", response.headers)
        code = await self.code(client_id)
        for extra in ({"resource": PUBLIC + "/other"}, {"code_verifier": "b" * 64},
                      {"redirect_uri": REDIRECT + "/"}, {"code_verifier": "a" * 42}):
            response = await self.exchange(client_id, code, **extra)
            self.assertEqual(response.status, 400, str(extra))
        other_client = await self.register()
        self.assertEqual((await self.exchange(other_client, code)).status, 400)
        self.assertEqual((await self.exchange(client_id, code)).status, 200)
        self.assertEqual((await self.exchange(client_id, code)).status, 400)

    async def test_csrf_origin_and_single_use(self):
        client_id = await self.register()
        data, headers = await self.form(client_id)
        for override in ({"Origin": "https://evil.test"}, {"Cookie": COOKIE + "=" + "b" * 43}, {"Origin": "null"}):
            response = await self.client.post("/authorize", data=data, headers={**headers, **override}, allow_redirects=False)
            self.assertEqual(response.status, 403)
        response = await self.client.post("/authorize", data=data, headers={"Cookie": headers["Cookie"]})
        self.assertEqual(response.status, 403)
        self.assertEqual(self.calls, [])
        response = await self.client.post("/authorize", data=data, headers=headers, allow_redirects=False)
        self.assertEqual(response.status, 303)
        response = await self.client.post("/authorize", data=data, headers=headers, allow_redirects=False)
        self.assertEqual(response.status, 403)
        self.assertEqual(self.calls, [SESSION])

    async def test_invalid_session_and_validator_timeout_are_sanitized(self):
        client_id = await self.register()
        data, headers = await self.form(client_id)
        data["session_token"] = "invalid-secret"
        response = await self.client.post("/authorize", data=data, headers=headers, allow_redirects=False)
        self.assertEqual(response.status, 400)
        self.assertNotIn("invalid-secret", await response.text())
        self.assertEqual(self.auth.db.execute("SELECT COUNT(*) FROM grants").fetchone()[0], 0)

        async def slow(token):
            await asyncio.sleep(1)

        self.auth.validate = slow
        self.auth.VALIDATE_TIMEOUT = 0.01
        data, headers = await self.form(client_id)
        response = await self.client.post("/authorize", data=data, headers=headers, allow_redirects=False)
        self.assertEqual(response.status, 502)
        self.assertEqual(self.auth.db.execute("SELECT COUNT(*) FROM forms").fetchone()[0], 0)

    async def test_concurrent_form_submission_calls_validator_once(self):
        client_id = await self.register()
        data, headers = await self.form(client_id)
        entered, release = asyncio.Event(), asyncio.Event()

        async def validate(token):
            self.calls.append(token)
            entered.set()
            await release.wait()

        self.auth.validate = validate
        first = asyncio.create_task(self.client.post("/authorize", data=data, headers=headers, allow_redirects=False))
        await asyncio.wait_for(entered.wait(), 1)
        second = await self.client.post("/authorize", data=data, headers=headers, allow_redirects=False)
        self.assertEqual(second.status, 403)
        release.set()
        self.assertEqual((await first).status, 303)
        self.assertEqual(self.calls, [SESSION])

    async def test_refresh_rotation_replay_revokes_entire_grant(self):
        client_id, tokens = await self.tokens()
        response = await self.refresh(client_id, tokens["refresh_token"])
        self.assertEqual(response.status, 200)
        new = await response.json()
        self.assertNotEqual(new["refresh_token"], tokens["refresh_token"])
        self.assertEqual((await self.access(new["access_token"])).status, 200)
        self.assertEqual((await self.refresh(client_id, tokens["refresh_token"])).status, 400)
        self.assertEqual((await self.access(new["access_token"])).status, 401)
        self.assertEqual((await self.access(tokens["access_token"])).status, 401)
        self.assertEqual((await self.refresh(client_id, new["refresh_token"])).status, 400)
        self.assertEqual(self.auth.db.execute("SELECT COUNT(*) FROM grants").fetchone()[0], 0)
        self.assertEqual(self.auth.db.execute("SELECT COUNT(*) FROM tokens").fetchone()[0], 0)

    async def test_refresh_binding_and_revoke_with_access_token(self):
        client_id, tokens = await self.tokens()
        other = await self.register()
        self.assertEqual((await self.refresh(other, tokens["refresh_token"])).status, 400)
        self.assertEqual((await self.refresh(client_id, tokens["refresh_token"], resource=PUBLIC + "/other")).status, 400)
        response = await self.client.post("/revoke", data={"client_id": other, "token": tokens["access_token"]})
        self.assertEqual(response.status, 200)
        self.assertEqual((await self.access(tokens["access_token"])).status, 200)
        response = await self.client.post("/revoke", data={"client_id": client_id, "token": tokens["access_token"]})
        self.assertEqual(response.status, 200)
        self.assertEqual((await self.access(tokens["access_token"])).status, 401)
        self.assertEqual((await self.refresh(client_id, tokens["refresh_token"])).status, 400)
        self.assertEqual(self.auth.db.execute("SELECT COUNT(*) FROM grants").fetchone()[0], 0)
        self.assertEqual((await self.client.post("/revoke", data={"client_id": client_id, "token": "unknown"})).status, 200)

    async def test_expiry_and_bounded_state(self):
        client_id, tokens = await self.tokens()
        with self.auth.db:
            self.auth.db.execute("UPDATE tokens SET expires=0 WHERE kind='access'")
        self.assertEqual((await self.access(tokens["access_token"])).status, 401)
        with self.auth.db:
            self.auth.db.execute("UPDATE grants SET expires=0")
        self.assertEqual((await self.refresh(client_id, tokens["refresh_token"])).status, 400)
        self.assertEqual(self.auth.db.execute("SELECT COUNT(*) FROM grants").fetchone()[0], 0)
        self.auth.MAX_FORMS = 1
        await self.form(client_id)
        self.assertEqual((await self.client.get("/authorize", params=self.params(client_id))).status, 503)
        with self.auth.db:
            self.auth.db.execute("UPDATE forms SET expires=0")
        await self.form(client_id)
        self.auth.MAX_CLIENTS = 1
        self.assertEqual((await self.client.post("/register", json={"redirect_uris": [REDIRECT]})).status, 503)

    async def test_expired_code_deletes_abandoned_session(self):
        client_id = await self.register()
        code = await self.code(client_id)
        with self.auth.db:
            self.auth.db.execute("UPDATE codes SET expires=0")
        self.assertEqual((await self.exchange(client_id, code)).status, 400)
        self.assertEqual(self.auth.db.execute("SELECT COUNT(*) FROM grants").fetchone()[0], 0)
        data, headers = await self.form(client_id)
        with self.auth.db:
            self.auth.db.execute("UPDATE forms SET expires=0")
        response = await self.client.post("/authorize", data=data, headers=headers, allow_redirects=False)
        self.assertEqual(response.status, 403)
        self.assertEqual(self.calls, [SESSION])

    async def test_revoking_used_refresh_revokes_new_tokens(self):
        client_id, tokens = await self.tokens()
        response = await self.refresh(client_id, tokens["refresh_token"])
        newer = await response.json()
        response = await self.client.post("/revoke", data={"client_id": client_id, "token": tokens["refresh_token"]})
        self.assertEqual(response.status, 200)
        self.assertEqual((await self.access(newer["access_token"])).status, 401)
        self.assertEqual((await self.refresh(client_id, newer["refresh_token"])).status, 400)

    async def test_scopes_control_refresh_and_default_to_mcp(self):
        for scope in (None, "mcp", "offline_access", "offline_access mcp"):
            client_id = await self.register()
            params = self.params(client_id)
            if scope is None:
                params.pop("scope")
            else:
                params["scope"] = scope
            response = await self.client.get("/authorize", params=params)
            self.assertEqual(response.status, 200)
            text = await response.text()
            nonce = re.search(r'name="csrf" value="([^"]+)"', text).group(1)
            response = await self.client.post("/authorize", data={"csrf": nonce, "session_token": SESSION},
                headers={"Origin": PUBLIC, "Cookie": COOKIE + "=" + response.cookies[COOKIE].value},
                allow_redirects=False)
            self.assertEqual(response.status, 303)
            query = parse_qs(urlsplit(response.headers["Location"]).query)
            self.assertEqual(query["iss"], [PUBLIC])
            response = await self.exchange(client_id, query["code"][0])
            self.assertEqual(response.status, 200)
            tokens = await response.json()
            self.assertEqual(set(tokens["scope"].split()), set((scope or "mcp").split()))
            self.assertEqual("refresh_token" in tokens, "offline_access" in (scope or ""))

    async def test_scope_errors_do_not_consume_code_or_refresh(self):
        client_id = await self.register()
        code = await self.code(client_id)
        response = await self.exchange(client_id, code, scope="mcp offline_access secret")
        self.assertEqual(await response.json(), {"error": "invalid_scope"})
        response = await self.exchange(client_id, code, scope="offline_access mcp")
        self.assertEqual(response.status, 200)
        tokens = await response.json()
        response = await self.refresh(client_id, tokens["refresh_token"], scope="secret")
        self.assertEqual(await response.json(), {"error": "invalid_scope"})
        response = await self.refresh(client_id, tokens["refresh_token"], scope="mcp")
        self.assertEqual(response.status, 200)
        narrower = await response.json()
        self.assertEqual(narrower["scope"], "mcp")
        # A rotated refresh credential retains the originally consented scope.
        response = await self.refresh(client_id, narrower["refresh_token"])
        self.assertEqual((await response.json())["scope"], "mcp offline_access")

    async def test_validator_unexpected_exception_is_generic(self):
        async def broken(token):
            raise RuntimeError("credentials=" + token)
        self.auth.validate = broken
        client_id = await self.register()
        data, headers = await self.form(client_id)
        response = await self.client.post("/authorize", data=data, headers=headers)
        self.assertEqual(response.status, 502)
        self.assertEqual(await response.json(), {"error": "temporarily_unavailable"})

    async def test_invalid_bearer_quota_does_not_block_valid_shared_peer(self):
        _, tokens = await self.tokens()
        for _ in range(601):
            response = await self.access("z" * 43)
        self.assertEqual(response.status, 429)
        response = await self.access(tokens["access_token"])
        self.assertEqual(response.status, 200)
        self.assertEqual((await response.json())["session_token"], SESSION)
        # Exhausted generic rate-table capacity cannot consume valid-grant capacity.
        self.auth.MAX_RATE_KEYS = 0
        self.assertEqual((await self.access(tokens["access_token"])).status, 200)

    async def test_valid_rate_limit_is_grant_based_persistent_and_expires(self):
        _, first = await self.tokens()
        _, second = await self.tokens()
        response = await self.access(first["access_token"])
        grant_id = (await response.json())["id"]
        with self.auth.db:
            self.auth.db.execute("UPDATE grants SET rate_count=600 WHERE id=?", (grant_id,))
        response = await self.client.post("/mcp", headers={"Authorization": "Bearer " + first["access_token"],
                "X-Forwarded-For": "198.51.100.42", "Forwarded": "for=198.51.100.42"})
        self.assertEqual(response.status, 429)
        self.assertEqual((await self.access(second["access_token"])).status, 200)
        await self.client.close()
        await self.start()
        self.assertEqual((await self.access(first["access_token"])).status, 429)
        with self.auth.db:
            self.auth.db.execute("UPDATE grants SET rate_start=0 WHERE id=?", (grant_id,))
        self.assertEqual((await self.access(first["access_token"])).status, 200)

    async def test_auth_middleware_leaves_non_auth_exceptions_to_caller(self):
        from aiohttp.test_utils import make_mocked_request
        request = make_mocked_request("POST", "/mcp")
        async def failing_handler(request):
            raise ValueError("application failure")
        with self.assertRaisesRegex(ValueError, "application failure"):
            await self.app.middlewares[-1](request, failing_handler)
        # A registered OAuth endpoint still sanitizes malformed request failures.
        response = await self.client.post("/register", data="broken", headers={"Content-Type": "application/json"})
        self.assertEqual(response.status, 400)
        self.assertEqual(await response.json(), {"error": "invalid_request"})

    async def test_rate_limits_persist_and_expire(self):
        for _ in range(10):
            response = await self.client.post("/register", json={"redirect_uris": ["https://evil.test/cb"]})
            self.assertEqual(response.status, 400)
        self.assertEqual((await self.client.post("/register", json={"redirect_uris": [REDIRECT]})).status, 429)
        await self.client.close()
        await self.start()
        self.assertEqual((await self.client.post("/register", json={"redirect_uris": [REDIRECT]})).status, 429)
        with self.auth.db:
            self.auth.db.execute("UPDATE rates SET start=0")
        await self.register()

    async def test_malformed_duplicate_oversized_and_cross_origin_requests(self):
        for payload in ('[]', '{"redirect_uris":[],"redirect_uris":[]}', 'x' * 17000):
            response = await self.client.post("/register", data=payload, headers={"Content-Type": "application/json"})
            self.assertEqual(response.status, 400)
            self.assertEqual(response.headers["Cache-Control"], "no-store")
        response = await self.client.post("/token", data="client_id=a&client_id=b",
                                          headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(response.status, 400)
        response = await self.client.post("/register", json={"redirect_uris": [REDIRECT]}, headers={"Origin": "https://evil.test"})
        self.assertEqual(response.status, 403)
        client_id = await self.register()
        params = list(self.params(client_id).items()) + [("resource", PUBLIC + "/mcp")]
        self.assertEqual((await self.client.get("/authorize", params=params)).status, 400)

    async def test_path_prefix_discovery(self):
        await self.client.close()
        # A different issuer intentionally requires a different state directory.
        self.directory.cleanup()
        self.directory = tempfile.TemporaryDirectory()
        await self.start(PUBLIC + "/bridge")
        response = await self.client.get("/.well-known/oauth-protected-resource/bridge/mcp")
        self.assertEqual((await response.json())["resource"], PUBLIC + "/bridge/mcp")
        response = await self.client.get("/.well-known/oauth-authorization-server/bridge")
        self.assertEqual((await response.json())["token_endpoint"], PUBLIC + "/bridge/token")
        response = await self.client.post("/bridge/mcp")
        self.assertIn("/oauth-protected-resource/bridge/mcp", response.headers["WWW-Authenticate"])

    async def test_resource_change_and_missing_key_fail_closed(self):
        await self.client.close()
        with self.assertRaisesRegex(ValueError, "different public resource"):
            build_auth(web.Application(), PUBLIC + "/other", self.directory.name, self.validator)
        Path(self.directory.name, "fernet.key").unlink()
        with self.assertRaisesRegex(ValueError, "no encryption key"):
            build_auth(web.Application(), PUBLIC, self.directory.name, self.validator)
        self.assertFalse(Path(self.directory.name, "fernet.key").exists())


if __name__ == "__main__":
    unittest.main()
