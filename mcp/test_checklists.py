"""Synthetic-only tests: never contact Wanderlog or load private trip fixtures."""

import asyncio
import copy
import json
import unittest
from unittest.mock import patch

import aiohttp

import checklists


def fixture():
    def block(identifier):
        return {"id": identifier, "type": "checklist", "title": "Repeated title",
                "metadata": {"preserve": True}, "items": [
                    {"id": 4, "checked": False, "text": {"ops": [{"insert": "Synthetic item"}]},
                     "extra": "preserved"}]}
    return {"success": True, "tripPlan": {"itinerary": {"sections": [
        {"id": 10, "heading": "Repeated heading", "blocks": [block(20), block(21)]},
        {"id": 11, "heading": "Repeated heading", "blocks": [block(22)]}]}}}


class Response:
    def __init__(self, data, status=200, raw=None):
        self.status = status
        self.raw = json.dumps(data).encode() if raw is None else raw
        self.content = self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def iter_chunked(self, size):
        for offset in range(0, len(self.raw), size):
            yield self.raw[offset:offset + size]


class Client:
    def __init__(self):
        self.data = fixture()
        self.calls = []
        self.before_post = None
        self.before_second_get = None
        self.after_post = None
        self.status = 200
        self.success = True
        self.failure = None
        self.get_count = 0
        self.bad_readback = False
        self.enforce_old_value = True

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, copy.deepcopy(kwargs)))
        if self.failure:
            raise self.failure
        if method == "GET":
            self.get_count += 1
            if self.get_count == 2 and self.before_second_get:
                self.before_second_get(self.data)
            if self.bad_readback and self.get_count > 2:
                return Response({}, 503)
            return Response(self.data)
        if self.before_post:
            self.before_post(self.data)
        if self.status != 200:
            return Response({}, self.status)
        operation, = kwargs["json"]["ops"]
        if set(operation) != {"p", "ld", "li"}:
            raise AssertionError("List replacement requires exactly p, ld and li")
        path = operation["p"]
        parent = self.data["tripPlan"]
        for key in path[:-1]:
            parent = parent[key]
        # Model API-level conflict validation, not bare JSON0 semantics.
        if path[-1] >= len(parent) or (self.enforce_old_value and parent[path[-1]] != operation["ld"]):
            return Response({}, 409)
        if self.success:
            parent[path[-1]] = copy.deepcopy(operation["li"])
        if self.after_post:
            self.after_post(self.data)
        return Response({"success": self.success})


def sections(data):
    return data["tripPlan"]["itinerary"]["sections"]


class ChecklistTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.client = Client()
        self.args = {"trip_key": "synthetic-trip", "itinerary_section_id": 10,
                     "checklist_block_id": 21}

    async def call(self, name="add_itinerary_checklist_items", args=None, token="synthetic-cookie-A"):
        result = await checklists.call_tool(self.client, token, name,
                                           {**self.args, "items": ["New item"]} if args is None else args)
        self.assertFalse(result["isError"])
        return json.loads(result["content"][0]["text"])

    def posts(self):
        return [call for call in self.client.calls if call[0] == "POST"]

    async def test_list_full_items_repeated_titles_and_headings(self):
        result = await self.call("list_itinerary_checklists", {"trip_key": "synthetic-trip"})
        self.assertEqual([b["block_id"] for b in result["checklists"]], [20, 21, 22])
        self.assertEqual(result["checklists"][1], {
            "section_id": 10, "heading": "Repeated heading", "block_id": 21,
            "title": "Repeated title", "items": sections(self.client.data)[0]["blocks"][1]["items"]})
        self.assertEqual(self.posts(), [])

    async def test_add_exact_section_guard_and_verified_readback(self):
        before = copy.deepcopy(self.client.data)
        result = await self.call(args={**self.args, "items": ["First", "Second"]})
        self.assertTrue(result["verified"])
        self.assertEqual((result["section_id"], result["block_id"]), (10, 21))
        self.assertEqual([item["id"] for item in result["items"]], [4, 5, 6])
        self.assertEqual(result["items"][1], {"id": 5, "checked": False,
                                              "text": {"ops": [{"insert": "First"}]}})
        self.assertEqual(sections(before)[0]["blocks"][0], sections(self.client.data)[0]["blocks"][0])
        self.assertEqual(sections(before)[1], sections(self.client.data)[1])
        op = self.posts()[0][2]["json"]["ops"][0]
        self.assertEqual(set(op), {"p", "ld", "li"})
        self.assertEqual(op["p"], ["itinerary", "sections", 0])
        self.assertEqual(op["ld"], sections(before)[0])
        self.assertEqual(op["li"]["blocks"][1]["metadata"], {"preserve": True})
        self.assertEqual(op["li"]["blocks"][0], sections(before)[0]["blocks"][0])
        self.assertEqual(self.client.get_count, 3)

    async def test_toggle_and_delete_exact_item(self):
        result = await self.call("toggle_itinerary_checklist_item", {**self.args, "item_id": 4, "checked": True})
        self.assertTrue(result["items"][0]["checked"])
        self.assertEqual(result["items"][0]["extra"], "preserved")
        self.assertFalse(sections(self.client.data)[0]["blocks"][0]["items"][0]["checked"])
        result = await self.call("delete_itinerary_checklist_item", {**self.args, "item_id": 4})
        self.assertEqual(result["items"], [])
        self.assertTrue(result["verified"])

    async def test_toggle_noop_still_reads_back_without_post(self):
        await self.call("toggle_itinerary_checklist_item", {**self.args, "item_id": 4, "checked": False})
        self.assertEqual(self.posts(), [])
        self.assertEqual(self.client.get_count, 2)

    async def test_empty_trip_and_empty_checklist(self):
        sections(self.client.data)[0]["blocks"][1]["items"] = []
        result = await self.call()
        self.assertEqual(result["items"][0]["id"], 0)
        self.client.data["tripPlan"]["itinerary"]["sections"] = []
        result = await self.call("list_itinerary_checklists", {"trip_key": "synthetic-trip"})
        self.assertEqual(result, {"checklists": []})

    async def test_invalid_arguments_fail_before_http(self):
        cases = []
        for field in ("itinerary_section_id", "checklist_block_id"):
            for value in (True, False, "21", 21.0, -1, None, 2**53):
                cases.append(("add_itinerary_checklist_items", {**self.args, "items": ["x"], field: value}))
        for value in ([], [""], ["  "], [3], "x", None):
            cases.append(("add_itinerary_checklist_items", {**self.args, "items": value}))
        for value in (True, "4", 4.0, -1, None):
            cases.append(("delete_itinerary_checklist_item", {**self.args, "item_id": value}))
        for value in (1, "true", None):
            cases.append(("toggle_itinerary_checklist_item", {**self.args, "item_id": 4, "checked": value}))
        for value in ("../escape", "https://example.test", "a?b", "", None):
            cases.append(("list_itinerary_checklists", {"trip_key": value}))
        cases.extend([("unknown", {}), ("list_itinerary_checklists", []),
                      ("add_itinerary_checklist_items", self.args),
                      ("list_itinerary_checklists", {"trip_key": "x", "extra": True})])
        for name, args in cases:
            with self.subTest(name=name, args=args), self.assertRaises(ValueError):
                await self.call(name, args)
        self.assertEqual(self.client.calls, [])

    async def test_missing_destination_never_falls_back(self):
        for replacement in ({"itinerary_section_id": 999}, {"checklist_block_id": 22}, {"checklist_block_id": 999}):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(ValueError, "not found"):
                await self.call(args={**self.args, "items": ["x"], **replacement})
        for name in ("delete_itinerary_checklist_item", "toggle_itinerary_checklist_item"):
            args = {**self.args, "item_id": 99}
            if name.startswith("toggle"):
                args["checked"] = True
            with self.assertRaisesRegex(ValueError, "Item ID not found"):
                await self.call(name, args)
        self.assertEqual(self.posts(), [])

    async def test_duplicates_rejected(self):
        def duplicate_section(data):
            sections(data)[1]["id"] = 10
        def duplicate_block(data):
            sections(data)[1]["blocks"][0]["id"] = 21
        def duplicate_item(data):
            items = sections(data)[0]["blocks"][1]["items"]
            items.append(copy.deepcopy(items[0]))
        for mutate in (duplicate_section, duplicate_block, duplicate_item):
            self.client = Client()
            mutate(self.client.data)
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                await self.call()
            self.assertEqual(self.posts(), [])

    async def test_invalid_raw_shape_and_wrong_block_type(self):
        mutations = [lambda d: d.pop("tripPlan"),
                     lambda d: sections(d)[0].update(id=True),
                     lambda d: sections(d)[0]["blocks"][1].update(items=None),
                     lambda d: sections(d)[0]["blocks"][1]["items"][0].update(checked=1),
                     lambda d: sections(d)[0]["blocks"][1]["items"][0].update(text={"ops": [{"insert": 3}]}),
                     lambda d: sections(d)[0]["blocks"][1].update(type="text")]
        for mutate in mutations:
            self.client = Client()
            mutate(self.client.data)
            with self.assertRaises(ValueError):
                await self.call()
            self.assertEqual(self.posts(), [])

    async def test_moved_block_and_concurrent_edit_conflict_no_retry(self):
        mutations = [lambda d: sections(d)[0]["blocks"].reverse(),
                     lambda d: sections(d).reverse(),
                     lambda d: sections(d)[0]["blocks"][1].update(title="Concurrent edit")]
        for mutate in mutations:
            self.client = Client()
            self.client.before_post = mutate
            with self.assertRaisesRegex(ValueError, "conflict"):
                await self.call()
            self.assertEqual(len(self.posts()), 1)
            self.assertEqual(self.client.get_count, 2)

    async def test_parent_identity_and_sibling_edits_guarded_for_all_writes(self):
        def replace_parent_identity(data):
            # The entire old block remains identical at the same numeric path.
            sections(data)[0]["id"] = 99

        def move_block_with_section_reorder(data):
            original, replacement = sections(data)
            replacement["blocks"] = original["blocks"]
            original["blocks"] = []
            sections(data).reverse()

        def edit_sibling(data):
            sections(data)[0]["blocks"][0]["title"] = "Concurrent sibling edit"

        def edit_heading(data):
            sections(data)[0]["heading"] = "Concurrent heading edit"

        writes = [("add_itinerary_checklist_items", {"items": ["x"]}),
                  ("toggle_itinerary_checklist_item", {"item_id": 4, "checked": True}),
                  ("delete_itinerary_checklist_item", {"item_id": 4})]
        for mutate in (replace_parent_identity, move_block_with_section_reorder,
                       edit_sibling, edit_heading):
            for name, extra in writes:
                with self.subTest(mutation=mutate.__name__, tool=name):
                    self.client = Client()
                    self.client.before_post = mutate
                    with self.assertRaisesRegex(ValueError, "conflict"):
                        await self.call(name, {**self.args, **extra})
                    self.assertEqual(len(self.posts()), 1)
                    self.assertEqual(self.client.get_count, 2)
                    target = next(block for section in sections(self.client.data)
                                  for block in section["blocks"] if block["id"] == 21)
                    self.assertEqual(len(target["items"]), 1)
                    self.assertFalse(target["items"][0]["checked"])

    async def test_bare_json0_readback_does_not_prove_atomic_conflict_protection(self):
        self.client.enforce_old_value = False
        self.client.before_post = lambda data: sections(data)[0].update(heading="External edit")
        result = await self.call()
        # Deliberately characterize the limitation: readback cannot detect a
        # concurrent edit overwritten by a server without old-value checks.
        self.assertTrue(result["verified"])
        self.assertEqual(sections(self.client.data)[0]["heading"], "Repeated heading")

    async def test_prewrite_freshness_check_rejects_changed_section_without_post(self):
        self.client.before_second_get = lambda data: sections(data)[0].update(heading="External edit")
        with self.assertRaisesRegex(ValueError, "changed before write"):
            await self.call()
        self.assertEqual(self.posts(), [])
        self.assertEqual(self.client.get_count, 2)

    async def test_other_section_concurrent_edit_preserved(self):
        self.client.before_post = lambda data: sections(data)[1].update(heading="Concurrent heading")
        result = await self.call()
        self.assertTrue(result["verified"])
        self.assertEqual(sections(self.client.data)[1]["heading"], "Concurrent heading")

    async def test_initial_reordered_blocks_resolve_current_indices(self):
        sections(self.client.data)[0]["blocks"].reverse()
        result = await self.call()
        self.assertEqual(result["block_id"], 21)
        operation = self.posts()[0][2]["json"]["ops"][0]
        self.assertEqual(operation["p"], ["itinerary", "sections", 0])
        self.assertEqual(operation["li"]["blocks"][0]["id"], 21)
        self.assertEqual(len(operation["li"]["blocks"][0]["items"]), 2)

    async def test_readback_mismatch_move_and_http_failure_unverified(self):
        def move(data):
            sections(data)[1]["blocks"].append(sections(data)[0]["blocks"].pop(1))
        for mutate in (lambda d: sections(d)[0]["blocks"][1]["items"].pop(), move,
                       lambda d: d.update(success=False)):
            self.client = Client()
            self.client.after_post = mutate
            with self.assertRaisesRegex(ValueError, "unverified"):
                await self.call()
            self.assertEqual(len(self.posts()), 1)
        self.client = Client()
        self.client.bad_readback = True
        with self.assertRaisesRegex(ValueError, "unverified"):
            await self.call()

    async def test_same_section_block_reorder_readback_uses_ids(self):
        self.client.after_post = lambda d: sections(d)[0]["blocks"].reverse()
        result = await self.call()
        self.assertTrue(result["verified"])
        self.assertEqual(result["block_id"], 21)

    async def test_rejected_post_and_redirect_no_retry(self):
        for status in (302, 401, 403, 409, 500):
            self.client = Client()
            self.client.status = status
            with self.assertRaises(ValueError):
                await self.call()
            self.assertEqual(len(self.posts()), 1)
        self.client = Client()
        self.client.success = False
        with self.assertRaisesRegex(ValueError, "confirm success"):
            await self.call()
        self.assertEqual(len(self.posts()), 1)

    async def test_safe_http_settings_and_per_request_cookie_isolation(self):
        for token in ("synthetic-cookie-A", "synthetic-cookie-B"):
            await self.call("list_itinerary_checklists", {"trip_key": "synthetic-trip"}, token)
        for index, (method, url, kwargs) in enumerate(self.client.calls):
            self.assertEqual(method, "GET")
            self.assertEqual(url, "https://wanderlog.com/api/tripPlans/synthetic-trip")
            self.assertEqual(kwargs["params"], {"clientSchemaVersion": "2"})
            self.assertFalse(kwargs["allow_redirects"])
            self.assertEqual(kwargs["timeout"].total, 20)
            self.assertEqual(kwargs["headers"]["Cookie"], "connect.sid=synthetic-cookie-" + "AB"[index])
        async with aiohttp.ClientSession() as unsafe_client:
            with self.assertRaisesRegex(ValueError, "DummyCookieJar"):
                await checklists.call_tool(unsafe_client, "synthetic-cookie", "list_itinerary_checklists", {"trip_key": "x"})

    async def test_invalid_cookie_rejected_before_network(self):
        for token in ("short", "secret; injected=yes", "secret\r\nvalue", "secret value", None):
            with self.assertRaisesRegex(ValueError, "Invalid session"):
                await self.call(token=token)
        self.assertEqual(self.client.calls, [])

    async def test_size_invalid_json_and_transport_errors_sanitized(self):
        for response in (Response({}, raw=b"not-json-secret"), Response({}, raw=b"\xff"),
                         Response([], raw=b"[]"), Response({}, raw=b"x" * 40)):
            with patch.object(self.client, "request", return_value=response), patch.object(checklists, "MAX_RESPONSE_BYTES", 32):
                with self.assertRaises(ValueError) as error:
                    await self.call()
                self.assertNotIn("secret", str(error.exception))
        for failure in (aiohttp.ClientError("credential-secret"), asyncio.TimeoutError("credential-secret")):
            self.client.failure = failure
            with self.assertRaises(ValueError) as error:
                await self.call()
            self.assertNotIn("credential-secret", str(error.exception))

    async def test_item_id_overflow_rejected(self):
        sections(self.client.data)[0]["blocks"][1]["items"][0]["id"] = checklists.MAX_ID
        with self.assertRaisesRegex(ValueError, "No safe numeric"):
            await self.call()
        self.assertEqual(self.posts(), [])

    async def test_historical_empty_flights_and_missing_heading(self):
        sections(self.client.data).append({"id": 12, "type": "flights", "blocks": None})
        sections(self.client.data)[0].pop("heading")
        original = copy.deepcopy(self.client.data)
        parsed = checklists._sections(self.client.data)
        self.assertEqual(parsed[-1]["blocks"], [])
        self.assertEqual(parsed[-1]["heading"], "")
        self.assertEqual(self.client.data, original)
        result = await self.call("list_itinerary_checklists", {"trip_key": "synthetic-trip"})
        self.assertEqual(result["checklists"][0]["heading"], "")
        self.assertEqual(len(result["checklists"]), 3)

    async def test_api_diagnostics_preserved_and_bounded(self):
        for response, expected in (
                (Response({"message": "Session expired"}, 401), "Session expired"),
                (Response({"error": {"message": "Edit conflict"}}, 409), "Edit conflict"),
                (Response({}, 503, raw=b"Temporarily unavailable"), "Temporarily unavailable"),
                (Response({"success": False, "text": "Access denied"}), "Access denied")):
            with patch.object(self.client, "request", return_value=response):
                with self.assertRaisesRegex(ValueError, expected):
                    await self.call()
        with patch.object(self.client, "request", return_value=Response({"error": "x" * 2000}, 400)):
            with self.assertRaises(ValueError) as error:
                await self.call()
            self.assertLess(len(str(error.exception)), 700)

    def test_tool_schemas(self):
        self.assertEqual(len(checklists.TOOL_DEFINITIONS), 4)
        for tool in checklists.TOOL_DEFINITIONS:
            schema = tool["inputSchema"]
            self.assertEqual(set(schema["required"]), set(schema["properties"]))
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(tool["annotations"]["readOnlyHint"], tool["name"].startswith("list_"))


if __name__ == "__main__":
    unittest.main()
