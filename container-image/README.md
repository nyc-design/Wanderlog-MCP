# Standalone image and startup contract

Build from the repository root:

```sh
docker build -f container-image/Dockerfile -t wanderlog-mcp:local .
docker run --rm -e PUBLIC_URL=https://your-workspace.example.com \
  -p 127.0.0.1:8080:8080 wanderlog-mcp:local
docker run --rm \
  --mount type=bind,src="$PWD/container-image/smoke-test.py",dst=/tmp/smoke-test.py,readonly \
  wanderlog-mcp:local python /tmp/smoke-test.py
```

The final image is Python slim Debian, not a Coder base image. The Go compiler
is confined to a separate build stage. The upstream CLI is fetched and verified
at commit `6d27c324c4aeca54ee1bf027d41e9f415e329734`; its go.mod requires
Go 1.26.6. The CLI is `/usr/local/bin/wanderlog`; the gateway is
`/opt/wanderlog-mcp/mcp/server.py`; dependencies come from `/mcp/requirements.txt`.
No credentials, default tokens, or local state are included. Set `PUBLIC_URL` to
the exact external HTTPS origin at runtime; there is no image default. Pass it
through the Coder agent/runtime environment or configure the private JSON file
described below after the workspace exists. The smoke test supplies an explicit reserved test-only origin.

Ordinary Docker runs execute the gateway in the foreground. Devcontainers use
`postStartCommand` to invoke `/usr/local/bin/start-gateway`: Python detaches a
flock-protected supervisor into a new session, duplicate calls are harmless, and a gateway crash
is retried after two seconds. Logs and the advisory lock live in `STATE_DIR`,
default `/home/coder/.local/share/wanderlog-mcp`, created with private permissions.
Use a private volume at that path for persistence; a bind mount must be writable
by UID 1000. Do not share one state directory across independent running containers.
Missing or invalid PUBLIC_URL produces one warning and exits without starting a
supervisor or creating a log. A missing gateway dependency causes logged retries; lifecycle completion alone
is not a readiness check. The smoke test verifies port readiness and restart.

## Coder project-workspace compatibility audit

Inspected `nyc-design/Coder-Workspaces` main at
`43b63702e91a4ac1caff57b3cc0cc4c67cd2ef42` on September 22, 2026:

- `workspace-templates/project-workspace/main.tf` uses
  `ghcr.io/coder/envbuilder:latest`, passes the agent init script to the envbuilder
  module, and attaches the shared workspace-startup script to the agent.
- `workspace-modules/workspace-envbuilder/main.tf` supplies
  `ENVBUILDER_INIT_SCRIPT`, `ENVBUILDER_SETUP_SCRIPT`, clone credentials, and
  `/workspaces/${project_name}`. The root setup script repairs ownership of
  `/home/coder` and `/workspaces` to `coder:coder` before agent initialization.
  Therefore the image defines a real coder user/group, writable home, and bash.
- `workspace-modules/workspace-startup/main.tf` runs sudo ownership repair,
  copies `/etc/skel` into home on first startup, and invokes
  `/usr/local/bin/run-workspace-inits >> /tmp/workspace-init.log 2>&1 || true`.
  This image deliberately does NOT provide that base-image initialization runner.
  Its absence is tolerated by the existing template; the template continues to
  create `/tmp/workspace-init.done`. This does not install any of the optional
  editors, extensions, language servers, or other tools from the Coder base.
- Passwordless sudo supports the template's ownership repair. Git supports
  workspace development, and curl plus CA certificates support agent download.
  No Coder agent binary or token is baked in: envbuilder injects the agent init.
- The inspected template does not set `ENVBUILDER_POST_START_SCRIPT_PATH`.
  Envbuilder normally executes postStartCommand as a lifecycle command directly;
  when that variable is set, it instead writes a script for the init command to
  execute. A deployment that adds it must also execute the generated script.
- The image CMD is not the envbuilder startup contract: envbuilder provides its
  own init command. The explicit devcontainer lifecycle hook starts the gateway
  independently of the template's optional base initialization pipeline.

This is source-level compatibility plus local Docker validation, not a live
Coder workspace provisioning test. The template uses an unpinned envbuilder
image; future template or envbuilder changes need another audit.

## CI publication

Pull requests build and smoke-test without registry credentials. Pushes to main
and manual dispatches build and test; publication requires main to also be the
repository default branch. Only the publish job receives packages:write. Image
names are normalized to lowercase, with `latest` and immutable `sha-<commit>`
tags. Actions use immutable commit pins. Publishing another branch is disabled.

## Configure an existing workspace without rebuilding

Run as `coder` (the same user as the gateway). Keep this file outside the repo:

```sh
export STATE_DIR="${STATE_DIR:-/home/coder/.local/share/wanderlog-mcp}"
install -d -m 0700 "$STATE_DIR"
(umask 077; printf '%s\n' '{"PUBLIC_URL":"https://your-workspace.example.com"}' > "$STATE_DIR/runtime.json")
chmod 0600 "$STATE_DIR/runtime.json"
/usr/local/bin/start-gateway --restart
```

Replace the example with the exact externally accessible HTTPS origin, without a
path or trailing slash. The JSON file must contain only `PUBLIC_URL`, be owned
by the gateway user, and have permissions exactly 0600. Symlinks are rejected;
configuration is parsed as JSON and never executed. The file overrides the
PUBLIC_URL environment variable. Both are optional only while unconfigured:
the gateway will not start without one valid value. Restart reloads configuration,
stops the existing supervisor and gateway, and launches a new instance without
rebuilding. Plain `start-gateway` is sufficient for the first configured start;
`--restart` is needed to replace an already-running instance.

Health checks must use the configured host, including an explicit port if present:

```sh
curl --fail -H 'Host: your-workspace.example.com' http://127.0.0.1:8080/healthz
```

The image smoke test sets a private JSON configuration with a reserved test HTTPS
origin and probes `/healthz` with its matching Host header. It also checks that
unconfigured startup exits once, rejects unsafe file permissions, and exercises
explicit restart in addition to duplicate-start and crash-recovery checks.

## Empty-repository bootstrap

Until an actual `main` branch exists, an initial feature-branch implementation
cannot open its intended PR against main, and the first GHCR publication is
blocked. Creating `refs/heads/main` requires separate explicit approval; pushing
the feature branch alone is not that approval. Recheck GitHub's default branch
after the first push before making subsequent commits.

Use the local Docker build and smoke-test commands above in the meantime. Manual
runs on a feature branch, when available, may build/test but cannot publish any
image tags. In particular, feature branches never update `latest`. Publication
remains restricted to a tested main revision with main designated as default.

The committed devcontainer consumes the prebuilt image
`ghcr.io/nyc-design/wanderlog-mcp:latest`; it does not build from source. Until the
first main publication, that registry-backed devcontainer cannot start. Bootstrap
with the standalone `docker build` and `docker run` commands above instead; this
does not require changing the committed devcontainer configuration or publishing
feature-branch images. The build context admits only the Dockerfile, startup
script, gateway server/auth modules, and requirements file—not tests, arbitrary
Python modules, SQLite databases, keys, logs, or other runtime files.

## Session-only reservation fix

The pinned upstream `currentUserID()` helper dereferenced a nil credential
object when no keychain/file credentials existed. The gateway intentionally uses
a per-request environment session instead, so reservation writes could panic
before mutation. `patches/session-only-credentials.patch` adds the nil check,
allowing the existing no-user-ID fallback. The synthetic regression fails with
the original source and passes with the patch. Every image build runs that test
before compiling the binary; no real account or session is used.
