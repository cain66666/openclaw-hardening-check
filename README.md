This script only reads. It fixes nothing and does not guarantee that you are safe. Green output means only that the checks listed below passed—and nothing more.

# OpenClaw hardening check

`openclaw-hardening-check.mjs` is a small, dependency-free, offline review of an OpenClaw installation. It reads local configuration, package metadata, plugin and skill manifests, file modes, and—on Linux—the running Gateway's entries in `/proc`. It does not change files, call OpenClaw commands, contact a registry, or make any network request.

## What it checks

- **Gateway bind:** reports whether `gateway.bind` is loopback-only, non-loopback, or runtime-dependent. An unset or `auto` bind inside a detected Docker, Podman, Kubernetes, or Fly container is treated as `0.0.0.0`, matching OpenClaw's container default. A running Linux Gateway is checked separately so a command-line or service override cannot hide behind a safe config value.
- **Gateway authentication:** models OpenClaw's config-first precedence for plaintext `gateway.auth.token` and `.password`. It recognizes `${VAR}`, `$VAR`, `secretref-env:VAR`, `__env__:VAR`, and structured SecretRefs before measuring a credential. Auth environment evidence comes from the matched Gateway process or the state `.env`, never from the auditor process. Secret values are never printed; the report contains only presence, source class, and length. Published example placeholders and tokens shorter than 24 characters are flagged.
- **CVE-2026-25253:** treats versions before `2026.1.29` as affected. The vulnerability let a query-string `gatewayUrl` trigger a WebSocket connection that disclosed the Gateway token. See the [NVD entry](https://nvd.nist.gov/vuln/detail/CVE-2026-25253) and the [OpenClaw advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-g8p2-7wf7-98mq).
- **Installation pin:** distinguishes an exact version or commit from moving targets such as `latest`, `beta`, or `main` when install provenance is supplied. npm and pnpm do not retain the original requested dist-tag in the installed package, so the script reports “cannot check” instead of guessing when that provenance is absent.
- **Secret-file permissions:** checks the config, config includes, `.env`, discovered `auth-profiles.json` files, and resolved file SecretRefs for group/world exposure or unexpected ownership.
- **Skills and plugins:** inventories bundled items—including `dist-runtime/extensions`—separately from items found in state, config-directory, managed, workspace, personal, configured, or npm project locations. Non-bundled items are marked for manual review, never labeled malicious.
- **Listening sockets:** on Linux, maps `/proc/net/tcp*` socket inodes back to Gateway entry-file or binary processes and flags every non-loopback TCP listener they own. A listener on the expected port whose owner cannot be verified produces “cannot check,” not “Gateway is not running.” The check still works from disk when the Gateway is stopped.
- **Control UI hardening:** flags dangerous device-auth, insecure-auth, and Host-header-origin overrides. It also warns when non-loopback shared-secret auth has no configured rate limit.

The paths and defaults follow the official [configuration documentation](https://docs.openclaw.ai/gateway/configuration), [configuration reference](https://docs.openclaw.ai/gateway/configuration-reference), [Gateway exposure runbook](https://docs.openclaw.ai/gateway/security/exposure-runbook), [skills documentation](https://docs.openclaw.ai/tools/skills), and [plugin management documentation](https://docs.openclaw.ai/plugins/manage-plugins).

## Run it

Copy the script to the machine that runs OpenClaw, then run it as the same OS user:

```bash
node openclaw-hardening-check.mjs
```

OpenClaw's default config is `~/.openclaw/openclaw.json`. The script also honors `OPENCLAW_CONFIG_PATH`, `OPENCLAW_STATE_DIR`, and `OPENCLAW_GATEWAY_PORT`.

Optional overrides are available for non-default layouts and reproducible pin checks:

```bash
node openclaw-hardening-check.mjs \
  --config /srv/openclaw/openclaw.json \
  --state-dir /srv/openclaw \
  --package-root /opt/openclaw/lib/node_modules/openclaw \
  --install-spec 2026.6.10
```

`--install-spec` must be the target originally used by the installer or deployment definition. Passing the currently installed version without verifying that provenance does not prove the deployment is pinned.

## Example output

The checker never emits the secret itself, so the publishable form records only its source and length:

```text
OpenClaw hardening check
Read-only and offline. Secret values are never printed.
Config: ~/.openclaw/openclaw.json

[PASS] Config: loaded ~/.openclaw/openclaw.json without printing its contents.
[PASS] Gateway bind: loopback; configured for local-only access.
[PASS] Gateway authentication: present via Gateway process environment bootstrap, length 48; value was not printed.
[PASS] Listening sockets: OpenClaw TCP listeners are loopback-only: 127.0.0.1:18789, [::1]:18789.
[PASS] CVE-2026-25253: installed package version 2026.6.10 is at or newer than 2026.1.29.
[PASS] Installation pin: exact target 2026.6.10 is recorded for this check.
[WARN] Third-party plugins: 1: example-plugin. Review it yourself; no malware verdict was attempted.

Summary: 1 issue(s) need attention; exit code 1.
```

Secret value: `[REDACTED — never present in output]`.

## Exit codes

| Code | Meaning                                                                                          |
| ---: | ------------------------------------------------------------------------------------------------ |
|  `0` | All checks that applied passed.                                                                  |
|  `1` | At least one problem, review item, or incomplete check needs attention.                          |
|  `2` | The command line is invalid, or the config could not be found, read, included, or parsed safely. |

## Deliberate limitations

- This is a local configuration and process-state check, not a remote exposure scanner. It makes no network connections, even to localhost.
- Run it in the same host/container context and as the same OS user as the Gateway. The auditor's own token/password environment is deliberately ignored.
- Socket ownership inspection currently requires Linux `/proc`. Other platforms receive an explicit “cannot check” result.
- A reverse proxy, container port publication, Tailscale configuration outside OpenClaw, firewall rule, or cloud load balancer can expose a loopback-looking deployment. Review those layers separately.
- Package files prove the installed version but normally cannot prove whether a package manager originally resolved `@latest`. Supply trusted deployment provenance with `--install-spec`.
- Third-party inventory is a prompt for human review, not a reputation or malware scan.

## Tests

The test suite uses only `node:test` and temporary directories:

```bash
node --test test/openclaw-hardening-check.test.mjs
```

## Author

Ilya Prudnikov — [cain-ai.com](https://cain-ai.com)

## License

[MIT](LICENSE)
