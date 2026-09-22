"""Exact-ID checklist operations with readback, not atomic compare-and-swap.

JSON0 ld/li does not itself check the old value. Wanderlog conflict validation
is unverified: external edits between fetch and POST may be overwritten, even
when readback succeeds. Avoid concurrent editing during mutations. HTTP 409 is
never retried. Caller must redact credentials from returned API diagnostics.
"""

import asyncio
import copy
import json
import re

import aiohttp


API_ORIGIN = "https://wanderlog.com/api"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_ID = 2**53 - 1
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=20)
_ID_SCHEMA = {"type": "integer", "minimum": 0, "maximum": MAX_ID}
_TARGET = {
    "trip_key": {"type": "string", "minLength": 1},
    "itinerary_section_id": _ID_SCHEMA,
    "checklist_block_id": _ID_SCHEMA,
}


def _definition(name, description, properties, read_only=False):
    return {
        "name": name,
        "description": description + ("" if read_only else " Avoid concurrent editing: atomic conflict protection is not verified."),
        "inputSchema": {"type": "object", "properties": properties,
                        "required": list(properties), "additionalProperties": False},
        "annotations": {"readOnlyHint": read_only, "destructiveHint": not read_only,
                        "idempotentHint": read_only, "openWorldHint": True},
    }


TOOL_DEFINITIONS = [
    _definition("list_itinerary_checklists", "List every checklist with exact numeric section, block and item IDs and full items.",
                {"trip_key": _TARGET["trip_key"]}, True),
    _definition("add_itinerary_checklist_items", "Append text items only to the exact section and checklist block. Returns verified readback; never retries writes.",
                {**_TARGET, "items": {"type": "array", "minItems": 1,
                                      "items": {"type": "string", "minLength": 1}}}),
    _definition("toggle_itinerary_checklist_item", "Set checked for an exact item ID in an exact section and block. Returns verified readback.",
                {**_TARGET, "item_id": _ID_SCHEMA, "checked": {"type": "boolean"}}),
    _definition("delete_itinerary_checklist_item", "Delete only an exact item ID in an exact section and block. Returns verified readback.",
                {**_TARGET, "item_id": _ID_SCHEMA}),
]


def _id(value, label):
    if type(value) is not int or not 0 <= value <= MAX_ID:
        raise ValueError(f"{label} must be an exact nonnegative safe integer ID")
    return value


def _validate_args(name, args):
    definition = next((tool for tool in TOOL_DEFINITIONS if tool["name"] == name), None)
    if definition is None:
        raise ValueError("Unknown checklist tool")
    if not isinstance(args, dict) or set(args) != set(definition["inputSchema"]["required"]):
        raise ValueError("Provide exactly the required checklist tool arguments")
    key = args["trip_key"]
    if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", key):
        raise ValueError("trip_key must be a trip key, not a URL or path")
    for field in ("itinerary_section_id", "checklist_block_id", "item_id"):
        if field in args:
            _id(args[field], field)
    if "checked" in args and type(args["checked"]) is not bool:
        raise ValueError("checked must be a boolean")
    if "items" in args and (not isinstance(args["items"], list) or not args["items"] or
                            any(not isinstance(item, str) or not item.strip() for item in args["items"])):
        raise ValueError("items must be a nonempty array of nonblank strings")


def _diagnostic(data):
    """Keep bounded API error text only; parent applies credential redaction."""
    if not isinstance(data, dict):
        return ""
    for key in ("message", "error", "text"):
        value = data.get(key)
        if isinstance(value, dict):
            nested = _diagnostic(value)
            if nested:
                return nested
        if isinstance(value, str) and value.strip():
            return ": " + " ".join(value[:1024].split())[:512]
    return ""


async def _request(client, token, method, path, **kwargs):
    # A shared session may pool connections, but must never retain account cookies.
    if isinstance(client, aiohttp.ClientSession) and not isinstance(client.cookie_jar, aiohttp.DummyCookieJar):
        raise ValueError("Checklist HTTP client requires DummyCookieJar for account isolation")
    try:
        async with client.request(method, API_ORIGIN + path,
                                  headers={"Cookie": "connect.sid=" + token,
                                           "User-Agent": "wanderlog-mcp/0.1"},
                                  allow_redirects=False, timeout=REQUEST_TIMEOUT, **kwargs) as response:
            raw = bytearray()
            limit = MAX_RESPONSE_BYTES if response.status == 200 else 65536
            async for chunk in response.content.iter_chunked(8192):
                raw.extend(chunk)
                if len(raw) > limit:
                    if response.status == 200:
                        raise ValueError("Checklist API response exceeds the safe size limit")
                    del raw[limit:]
                    break
            try:
                data = json.loads(raw)
            except (UnicodeError, json.JSONDecodeError):
                if response.status == 200:
                    raise ValueError("Checklist API returned invalid JSON; list again before writing") from None
                data = {"text": raw.decode("utf-8", errors="replace")}
            detail = _diagnostic(data)
            if response.status == 409:
                raise ValueError("Checklist conflict: list again before a new write; no automatic retry" + detail)
            if response.status != 200:
                raise ValueError(f"Checklist API returned HTTP {response.status}; check access and list again before writing" + detail)
            if not isinstance(data, dict) or data.get("success") is not True:
                raise ValueError("Checklist API did not confirm success; list again before writing" + detail)
            return data
    except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError, json.JSONDecodeError):
        raise ValueError("Checklist request failed or returned invalid JSON; list again before writing, do not blindly retry") from None


def _sections(data):
    try:
        sections = copy.deepcopy(data["tripPlan"]["itinerary"]["sections"])
        if not isinstance(sections, list):
            raise TypeError
        section_ids, block_ids = set(), set()
        for section in sections:
            section.setdefault("heading", "")
            if section.get("blocks") is None:
                section["blocks"] = []
            sid = _id(section["id"], "Upstream section ID")
            if sid in section_ids:
                raise ValueError("Duplicate section ID: exact destination is ambiguous")
            section_ids.add(sid)
            if not isinstance(section["heading"], str) or not isinstance(section["blocks"], list):
                raise TypeError
            for block in section["blocks"]:
                bid = _id(block["id"], "Upstream block ID")
                if bid in block_ids:
                    raise ValueError("Duplicate block ID: exact destination is ambiguous")
                block_ids.add(bid)
                if block.get("type") != "checklist":
                    continue
                if not isinstance(block["title"], str) or not isinstance(block["items"], list):
                    raise TypeError
                item_ids = set()
                for item in block["items"]:
                    iid = _id(item["id"], "Upstream item ID")
                    if iid in item_ids:
                        raise ValueError("Duplicate item ID: exact item is ambiguous")
                    item_ids.add(iid)
                    if type(item["checked"]) is not bool or not isinstance(item["text"]["ops"], list):
                        raise TypeError
                    if any(not isinstance(op, dict) or not isinstance(op.get("insert"), str)
                           for op in item["text"]["ops"]):
                        raise TypeError
        return sections
    except (KeyError, TypeError, AttributeError):
        raise ValueError("Unexpected raw trip checklist structure; no safe exact destination") from None


def _target(sections, args):
    for section_index, section in enumerate(sections):
        if section["id"] != args["itinerary_section_id"]:
            continue
        for block_index, block in enumerate(section["blocks"]):
            if block["id"] == args["checklist_block_id"]:
                if block.get("type") != "checklist":
                    raise ValueError("Exact block is not a checklist")
                return section_index, block_index, section, block
        raise ValueError("Checklist block ID not found in the specified section; list again, never fall back")
    raise ValueError("Itinerary section ID not found; list again, never fall back")


def _summary(section, block):
    return {"section_id": section["id"], "heading": section["heading"],
            "block_id": block["id"], "title": block["title"], "items": block["items"]}


def _result(value):
    return {"content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False)}],
            "isError": False}


async def call_tool(client, token, name, args):
    """Return an MCP tool result, or raise a sanitized actionable ValueError."""
    _validate_args(name, args)
    if not isinstance(token, str) or not 8 <= len(token) <= 4096 or any(
            ord(c) <= 32 or ord(c) >= 127 or c in ';,\"\\' for c in token):
        raise ValueError("Invalid session token")
    path = "/tripPlans/" + args["trip_key"]

    async def read():
        return _sections(await _request(client, token, "GET", path,
                                        params={"clientSchemaVersion": "2"}))

    sections = await read()
    if name == "list_itinerary_checklists":
        return _result({"checklists": [_summary(section, block) for section in sections
                                       for block in section["blocks"] if block.get("type") == "checklist"]})
    si, bi, section, old = _target(sections, args)
    new = copy.deepcopy(old)
    if name == "add_itinerary_checklist_items":
        next_id = max((item["id"] for item in new["items"]), default=-1) + 1
        if next_id + len(args["items"]) - 1 > MAX_ID:
            raise ValueError("No safe numeric item IDs available in this checklist")
        new["items"].extend({"id": next_id + index, "checked": False,
                             "text": {"ops": [{"insert": text}]}}
                            for index, text in enumerate(args["items"]))
    else:
        item = next((item for item in new["items"] if item["id"] == args["item_id"]), None)
        if item is None:
            raise ValueError("Item ID not found in the exact checklist; list again, never fall back")
        if name == "toggle_itinerary_checklist_item":
            item["checked"] = args["checked"]
        else:
            new["items"].remove(item)
    if new != old:
        # sections is a list: replacing an element requires ld/li, not od/oi.
        # Include the parent identity and full old contents for upstream conflict
        # validation. JSON0 alone does not guarantee old-value comparison; the
        # API must enforce it for this to provide atomic concurrency protection.
        updated_section = copy.deepcopy(section)
        updated_section["blocks"][bi] = new
        latest_sections = await read()
        latest_si, _, latest_section, _ = _target(latest_sections, args)
        if latest_si != si or latest_section != section:
            raise ValueError("Checklist section changed before write; list again and review before retrying")
        await _request(client, token, "POST", path + "/applyOps", json={"ops": [{
            "p": ["itinerary", "sections", si], "ld": section, "li": updated_section}]})
    try:
        _, _, verified_section, verified_block = _target(await read(), args)
        if verified_block != new:
            raise ValueError("Readback differs from the requested checklist")
    except ValueError as error:
        raise ValueError("Checklist write outcome is unverified: list again and inspect before another write. " + str(error)) from None
    return _result({"verified": True, **_summary(verified_section, verified_block)})
