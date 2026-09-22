import json
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from aiohttp.test_utils import TestClient, TestServer
import server


class FakeAuth:
    async def authenticate(self, request):
        token = request.headers.get('Authorization', '')
        if not token.startswith('Bearer '):
            raise server.web.HTTPUnauthorized()
        return {'id': token, 'session_token': token[7:]}


class ServerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.calls = []
        async def runner(token, method, params):
            self.calls.append((token, method, params))
            if method == 'tools/list':
                return {'result': {'tools': [{'name': 'list_trips'}, {'name': 'config_get'}]}}
            return {'result': {'content': [{'type': 'text', 'text': token}]}}
        self.runner = AsyncMock(side_effect=runner)
        self.temp = tempfile.TemporaryDirectory()
        with patch('server.build_auth', return_value=FakeAuth()):
            self.client = TestClient(TestServer(server.make_app(
                'https://mcp.example.com', self.temp.name, self.runner)))
        await self.client.start_server()
        self.headers = {'Host': 'mcp.example.com', 'Authorization': 'Bearer account-A',
                        'Accept': 'application/json, text/event-stream'}

    async def asyncTearDown(self):
        await self.client.close()
        self.temp.cleanup()

    async def rpc(self, method, params=None, headers=None):
        return await self.client.post('/mcp', headers=headers or self.headers,
            json={'jsonrpc': '2.0', 'id': 9, 'method': method, 'params': params or {}})

    async def test_initialize_and_allowlist(self):
        response = await self.rpc('initialize', {'protocolVersion': '2025-11-25'})
        self.assertEqual((await response.json())['result']['protocolVersion'], '2025-11-25')
        response = await self.rpc('tools/list')
        tools = (await response.json())['result']['tools']
        self.assertEqual([t['name'] for t in tools], ['list_trips'])
        self.assertTrue(tools[0]['annotations']['readOnlyHint'])
        response = await self.rpc('tools/call', {'name': 'config_get'})
        self.assertEqual((await response.json())['error']['code'], -32602)
        self.assertEqual(len(self.calls), 1)

    async def test_account_isolation(self):
        for token in ['account-A', 'account-B']:
            headers = dict(self.headers, Authorization='Bearer ' + token)
            await self.rpc('tools/call', {'name': 'list_trips'}, headers)
        self.assertEqual([c[0] for c in self.calls], ['account-A', 'account-B'])

    async def test_request_boundaries(self):
        response = await self.rpc('ping', headers=dict(self.headers, Host='attacker.example'))
        self.assertEqual(response.status, 421)
        response = await self.rpc('ping', headers=dict(self.headers, Origin='https://evil.example'))
        self.assertEqual(response.status, 403)
        headers = dict(self.headers)
        del headers['Authorization']
        self.assertEqual((await self.rpc('ping', headers=headers)).status, 401)
        response = await self.client.post('/mcp', headers=self.headers, json=[])
        self.assertEqual((await response.json())['error']['code'], -32600)
        response = await self.rpc('tools/call', {'name': ['list_trips']})
        self.assertNotEqual(response.status, 500)

    async def test_numeric_json_fuzz(self):
        headers = dict(self.headers, **{'Content-Type': 'application/json'})
        for value in ['NaN', 'Infinity', '-Infinity', '1' * 4400]:
            for position in ['id', 'argument']:
                with self.subTest(value=value[:20], position=position):
                    if position == 'id':
                        body = '{"jsonrpc":"2.0","method":"ping","id":' + value + '}'
                    else:
                        body = ('{"jsonrpc":"2.0","id":9,"method":"tools/call",'
                                '"params":{"name":"list_trips","arguments":{"value":'
                                + value + '}}}')
                    response = await self.client.post('/mcp', headers=headers, data=body)
                    self.assertEqual(response.status, 200)
                    self.assertEqual(await response.json(), {'jsonrpc': '2.0', 'id': None,
                        'error': {'code': -32700, 'message': 'Parse error'}})
        self.runner.assert_not_awaited()

    async def test_invalid_numeric_request_ids(self):
        for value in [True, False, 1.5, None]:
            with self.subTest(value=value):
                response = await self.client.post('/mcp', headers=self.headers,
                    json={'jsonrpc': '2.0', 'id': value, 'method': 'ping'})
                self.assertEqual(response.status, 200)
                self.assertEqual((await response.json())['error']['code'], -32600)
        self.runner.assert_not_awaited()

    async def test_tool_arguments_must_be_an_object(self):
        for arguments in [None, [], ['trip'], '', 'trip', 0, 42, False]:
            with self.subTest(arguments=arguments):
                response = await self.rpc('tools/call',
                    {'name': 'list_trips', 'arguments': arguments})
                self.assertEqual(response.status, 200)
                body = await response.json()
                self.assertEqual(body['id'], 9)
                self.assertEqual(body['error']['code'], -32602)
        self.runner.assert_not_awaited()
        for params in [{'name': 'list_trips'}, {'name': 'list_trips', 'arguments': {}},
                       {'name': 'list_trips', 'arguments': {'format': 'json'}}]:
            response = await self.rpc('tools/call', params)
            self.assertIn('result', await response.json())
            self.runner.assert_awaited_with('account-A', 'tools/call', params)

    async def test_credential_errors_are_suppressed(self):
        secret = 'connect.sid=private-session-sentinel'
        upstream_errors = [
            {'error': {'code': -32000, 'message': secret, 'data': {'cookie': secret}}},
            {'result': {'isError': True, 'content': [{'type': 'text', 'text': secret}],
                        'structuredContent': {'cookie': secret}, '_meta': {'cookie': secret}}},
        ]
        self.runner.side_effect = None
        with self.assertNoLogs('aiohttp.server', level='WARNING'):
            for upstream in upstream_errors:
                with self.subTest(upstream=upstream):
                    self.runner.return_value = upstream
                    response = await self.rpc('tools/call', {'name': 'list_trips'})
                    self.assertEqual(response.status, 200)
                    text = await response.text()
                    self.assertNotIn(secret, text)
                    body = json.loads(text)
                    if 'error' in upstream:
                        self.assertEqual(body['error'],
                            {'code': -32603, 'message': 'Wanderlog request failed'})
                    else:
                        self.assertEqual(body['result'], {'isError': True, 'content': [
                            {'type': 'text', 'text': 'Wanderlog request failed. Check arguments or reconnect your account.'}]})
            for exception in [RuntimeError, ValueError, OSError, TypeError, KeyError]:
                with self.subTest(exception=exception):
                    self.runner.side_effect = exception(secret)
                    response = await self.rpc('tools/call', {'name': 'list_trips'})
                    self.assertEqual(response.status, 200)
                    text = await response.text()
                    self.assertNotIn(secret, text)
                    self.assertEqual(json.loads(text)['error'],
                        {'code': -32603, 'message': 'Wanderlog request failed'})

    async def test_fragmented_session_validation_and_size_limit(self):
        class FragmentedContent:
            def __init__(self, chunks):
                self.chunks = iter(chunks)

            async def read(self, size):
                return next(self.chunks, b'')

            async def iter_chunked(self, size):
                for chunk in self.chunks:
                    yield chunk

        for size in [16, 65536, 65537]:
            with self.subTest(size=size):
                raw = b'{"user":{"id":1}}'
                raw += b' ' * max(0, size - len(raw))
                chunks = [raw[:5]] + [raw[i:i + 8192] for i in range(5, len(raw), 8192)]
                response = MagicMock(status=200)
                response.content = FragmentedContent(chunks)
                client = MagicMock()
                client.get.return_value.__aenter__.return_value = response
                if size > 65536:
                    with self.assertRaisesRegex(ValueError, 'Unexpected session response'):
                        await server.validate_session(client, 'valid-session-token')
                else:
                    self.assertIsNone(await server.validate_session(client, 'valid-session-token'))
                client.get.assert_called_once_with('https://wanderlog.com/api/user',
                    headers={'Cookie': 'connect.sid=valid-session-token',
                             'User-Agent': 'wanderlog-mcp/0.1'}, allow_redirects=False)

    async def test_cli_cumulative_output_budget(self):
        init = json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': {'padding': 'x' * 160}}) + '\n'
        notification = json.dumps({'jsonrpc': '2.0', 'method': 'notifications/message',
                                   'params': {'padding': 'x' * 160}}) + '\n'
        result = json.dumps({'jsonrpc': '2.0', 'id': 2, 'result': {'content': []}}) + '\n'
        with tempfile.TemporaryDirectory() as tmp:
            binary = os.path.join(tmp, 'fake-cli')
            for notifications in ['', notification * 3]:
                with open(binary, 'w') as output:
                    output.write('#!/usr/bin/env python3\nimport json, sys\n'
                        'for line in sys.stdin:\n'
                        '    req = json.loads(line)\n'
                        '    if "id" not in req: continue\n'
                        f'    reply = {init!r} if req["id"] == 1 else {notifications + result!r}\n'
                        '    sys.stdout.write(reply)\n    sys.stdout.flush()\n')
                os.chmod(binary, 0o700)
                total = len((init + notifications + result).encode())
                for budget in [total, total - 1]:
                    with self.subTest(notifications=bool(notifications), budget=budget):
                        with patch('server.MAX_OUTPUT', budget):
                            if budget == total:
                                reply = await server.cli_rpc('session-a', 'tools/list', {}, binary)
                                self.assertEqual(reply['result'], {'content': []})
                            else:
                                with self.assertRaisesRegex(RuntimeError, 'Upstream output limit exceeded'):
                                    await server.cli_rpc('session-a', 'tools/list', {}, binary)

    async def test_invalid_cookie_rejected_without_network(self):
        for token in ['short', 'abc; other=secret', 'abc\r\nother', 'a bbbbbbbb']:
            with self.assertRaises(ValueError):
                await server.validate_session(None, token)

    async def test_cli_process_isolated_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = os.path.join(tmp, 'fake-cli')
            with open(binary, 'w') as output:
                output.write('''#!/usr/bin/env python3
import json, os, sys
for line in sys.stdin:
    req=json.loads(line)
    if 'id' not in req: continue
    result={} if req['method']=='initialize' else {'token':os.environ['WANDERLOG_AUTH_SESSION_COOKIE'], 'leaked':os.environ.get('SENTINEL_SECRET'), 'home':os.environ['HOME']}
    print(json.dumps({'jsonrpc':'2.0','id':req['id'],'result':result}), flush=True)
''')
            os.chmod(binary, 0o700)
            with patch.dict(os.environ, {'SENTINEL_SECRET': 'must-not-inherit'}):
                result = await server.cli_rpc('session-a', 'tools/list', {}, binary)
            self.assertEqual(result['result']['token'], 'session-a')
            self.assertIsNone(result['result']['leaked'])
            self.assertFalse(os.path.exists(result['result']['home']))


if __name__ == '__main__':
    unittest.main()
