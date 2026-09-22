# Wanderlog MCP

Unofficial, read-only Wanderlog connector for ChatGPT and OAuth-capable remote MCP
clients. Each user connects their own account by providing the **value of their
Wanderlog `connect.sid` cookie** on the connector's consent page. No passwords.

## Contents

- `mcp/`: Python HTTP MCP gateway, OAuth public-client flow, encrypted persistence,
  and offline tests.
- `container-image/`: standalone lean image with pinned Wanderlog CLI and startup
  supervisor. No Coder-Workspaces base image or shared init scripts.
- `.github/workflows/`: tests, container smoke test, and GHCR image publication.
- `.devcontainer/devcontainer.json`: consumes the prebuilt image and launches the
  gateway through the devcontainer lifecycle.
- `.likec4/architecture.c4`: maintained architecture model.

## Deployment

Publish the image with the repository's GitHub workflow before launching an
image-based workspace. The first launch cannot pull an image that has not yet
been published. See `container-image/README.md` for the bootstrap build and
runtime configuration instructions.

Use the existing envbuilder project template with this repository. No changes to
that template or its base image are required by this repository. Infrastructure
may still invoke its own startup hooks; this service does not depend on them.

1. Configure the gateway's `PUBLIC_URL` to the **exact HTTPS origin** of the
   workspace's Coder public port-forwarding URL for port **8080** (no `/mcp`
   suffix and no trailing path). Do not commit your personal URL.
2. Keep `STATE_DIR` in persistent private storage; default:
   `/home/coder/.local/share/wanderlog-mcp`. It contains the encryption key and
   database. Back them up together, privately.
3. Start the gateway using the image's `start-gateway` command. On configured
   subsequent starts, `.devcontainer/devcontainer.json` invokes it automatically.
4. Share port 8080 publicly through Coder. The proxy must preserve the public
   `Host` and browser `Origin`. Coder supplies TLS; the container listens on HTTP.
5. Add `https://YOUR-CODER-PORT-HOST/mcp` as a custom MCP connection in ChatGPT,
   selecting OAuth. Discovery and dynamic public-client registration are built in;
   no client secret is required. Follow the account connection page.

The workspace must remain running. A stopped workspace is not a hosted service.
Changing the public origin requires new OAuth connections and a new state
directory; tokens are deliberately bound to their original resource.

### Getting the session token

On your own computer, sign in to Wanderlog in a browser. Open developer tools,
then **Application / Storage → Cookies → `https://wanderlog.com`**. Find
`connect.sid` and copy only its **Value** into the connector's account connection
page. Do not paste it into a chat message, issue, shell command, or repository.
Treat it like a password. When the session expires, reconnect with a fresh value.

This service is not affiliated with Wanderlog. Users must trust the operator:
encryption at rest does not prevent the running service or host administrator
from accessing credentials. The cookie itself can authorize more than the
read-only tools this gateway exposes. Do not connect to an operator you distrust.

## Available tools

`list_trips`, `get_trip`, `get_trip_plan`, `get_itinerary`, `list_places`,
`list_sections`, `get_flights`, and `get_trip_sections`.

The allowlist is enforced on both discovery and execution. Upstream account,
configuration, arbitrary API, and write tools are not exposed. Every tool request
gets a fresh CLI process, temporary HOME, and minimal environment for that user's
session. Concurrency is capped at eight, with bounded request and process timeouts.

## Authentication and privacy

- Authorization code flow with mandatory S256 PKCE and exact resource binding.
- Per-client exact redirect registration. HTTPS callback host allowlist defaults
  to `chatgpt.com,chat.openai.com`; set `AUTH_CALLBACK_HOSTS` only for clients you
  intend to support. Do not use wildcards.
- Separate opaque access and rotating refresh tokens; only their hashes persist.
  Clients request `mcp offline_access` to obtain refresh tokens; `mcp` alone
  grants access without a refresh token.
- One-hour access lifetime; account grants expire after 30 days or earlier if the
  upstream session expires. Reconnect when required.
- `POST /revoke` accepts an access or refresh token with its `client_id` and
  revokes the associated grant, deleting the stored encrypted session. Revoking a
  connector grant does not invalidate the original Wanderlog browser session.
- Session credentials encrypted with Fernet; database/key files permission 0600.
- Application access logging and CLI stderr are disabled. Configure the proxy
  and any observability services not to capture sensitive headers, queries, bodies,
  or response content. OAuth authorization codes necessarily travel in redirects;
  Wanderlog session credentials never do.
- The image build uses an allowlisted Docker context. No real accounts are needed
  for builds or tests; examples contain only placeholders.

This is a single-instance service with lightweight abuse limits, not a production
identity provider for an untrusted high-volume public audience. Proxy-level
connection limits are recommended. IP limits intentionally do not trust forwarded
headers; users behind the same Coder proxy share those limits. The unofficial
upstream API may change without notice.

## Development

```sh
python3 -m venv .venv
.venv/bin/pip install -r mcp/requirements.txt
.venv/bin/python -m unittest discover -s mcp -p 'test_*.py' -v
docker build -f container-image/Dockerfile -t wanderlog-mcp:local .
```

Tests mock Wanderlog. A successful local build does **not** prove a live Wanderlog
cookie or ChatGPT account connection works; complete that acceptance test on the
actual Coder HTTPS URL without sharing credentials with contributors.

Upstream: `https://github.com/denysvitali/wanderlog-cli`, pinned in the Dockerfile.
The upstream license is preserved in the image.
