# Architecture and development

Standalone Python aiohttp gateway, SQLite encrypted credential storage, and an
upstream Go Wanderlog CLI executable. No Coder-Workspaces runtime image or init
script dependencies. Coder/envbuilder supplies infrastructure and public HTTPS.

## Boundaries
- OAuth public-client authorization code flow, mandatory S256 PKCE and exact
  resource binding. Users enter only a Wanderlog `connect.sid` cookie value.
- Separate opaque MCP tokens; upstream credentials never serve as bearer tokens.
- Every tool request starts an isolated CLI stdio subprocess with a temporary
  HOME and minimal environment. No shared upstream clients, config, or caches.
- Explicit read/write itinerary tool allowlists; never expose upstream config/account tools.
- Write access requires per-grant browser consent; existing grants remain read-only.
- Canonical external origin comes from PUBLIC_URL, not incoming proxy headers.
- Database and encryption key belong in persistent private STATE_DIR, never Git.

Maintained architecture: `.likec4/architecture.c4`.

## Checks
```sh
python3 -m venv .venv
.venv/bin/pip install -r mcp/requirements.txt
.venv/bin/python -m unittest discover -s mcp -p 'test_*.py' -v
docker build -f container-image/Dockerfile -t wanderlog-mcp:local .
```

Keep dependencies pinned. Do not log HTTP queries, bodies, cookies, authorization
headers, upstream stderr, or credential-bearing exceptions. Mock Wanderlog in
normal CI: never require real accounts or secrets for tests. Test account
isolation, PKCE, refresh rotation, revocation, and encrypted persistence.
