import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  configuredBind,
  detectContainerEnvironment,
  isGatewayArgv,
  resolveGatewayCredential,
} from "../openclaw-hardening-check.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const script = path.join(root, "openclaw-hardening-check.mjs");
const TEST_PORT = 40000 + (process.pid % 20000);

function fixture(version = "2026.6.10", { configOutsideState = false } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-hardening-check-"));
  const home = path.join(directory, "home");
  const stateDir = path.join(home, ".openclaw");
  const packageRoot = path.join(directory, "package");
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(packageRoot, { recursive: true, mode: 0o700 });
  fs.writeFileSync(
    path.join(packageRoot, "package.json"),
    `${JSON.stringify({ name: "openclaw", version })}\n`,
    { mode: 0o600 },
  );
  return {
    directory,
    home,
    stateDir,
    packageRoot,
    configPath: configOutsideState
      ? path.join(directory, "config", "openclaw.json")
      : path.join(stateDir, "openclaw.json"),
  };
}

function run(f, extraArgs = [], env = {}) {
  return spawnSync(
    process.execPath,
    [
      script,
      "--config",
      f.configPath,
      "--state-dir",
      f.stateDir,
      "--package-root",
      f.packageRoot,
      ...extraArgs,
    ],
    {
      encoding: "utf8",
      env: { HOME: f.home, PATH: "", ...env },
    },
  );
}

function writeConfig(f, value) {
  fs.mkdirSync(path.dirname(f.configPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(f.configPath, typeof value === "string" ? value : `${JSON.stringify(value)}\n`, {
    mode: 0o600,
  });
}

test("a missing config is explained without a stack trace and exits 2", () => {
  const f = fixture();
  const result = run(f, ["--install-spec", "2026.6.10"]);
  assert.equal(result.status, 2);
  assert.match(result.stdout, /Could not read .* \(ENOENT\)/u);
  assert.doesNotMatch(`${result.stdout}${result.stderr}`, /\n\s+at\s/u);
});

test("a safe JSON5 config and the Cain pin pass", () => {
  const f = fixture();
  writeConfig(
    f,
    `{
      // OpenClaw accepts JSON5.
      meta: { lastTouchedVersion: '2026.6.10', },
      gateway: {
        mode: 'local',
        bind: 'loopback',
        port: ${TEST_PORT},
        auth: { mode: 'token', token: '0123456789abcdef0123456789abcdef', },
      },
    }`,
  );
  const result = run(f, ["--install-spec", "2026.6.10"]);
  assert.equal(result.status, 0, result.stdout);
  assert.match(result.stdout, /installed package version 2026\.6\.10 is at or newer/u);
  assert.match(result.stdout, /exact target 2026\.6\.10/u);
  assert.match(result.stdout, /Summary: No security problems found; exit code 0\./u);
});

test("versions before 2026.1.29 are reported as affected", () => {
  const f = fixture("2026.1.28");
  writeConfig(f, {
    gateway: {
      bind: "loopback",
      port: TEST_PORT,
      auth: { mode: "token", token: "0123456789abcdef0123456789abcdef" },
    },
  });
  const result = run(f, ["--install-spec", "2026.1.28"]);
  assert.equal(result.status, 1);
  assert.match(result.stdout, /older than fixed version 2026\.1\.29/u);
});

test("secret values never appear in output", () => {
  const f = fixture();
  const secret = "ULTRA_SECRET_CANARY_7b16431d8c694fee";
  writeConfig(f, {
    gateway: {
      bind: "lan",
      port: TEST_PORT,
      auth: { mode: "token", token: secret },
    },
  });
  const result = run(f, ["--install-spec", "2026.6.10"]);
  assert.equal(result.status, 1);
  assert.doesNotMatch(`${result.stdout}${result.stderr}`, new RegExp(secret, "u"));
  assert.match(result.stdout, new RegExp(`length ${secret.length}`, "u"));
});

test("published placeholder tokens are rejected without being echoed", () => {
  const f = fixture();
  const placeholder = "change-me-now";
  writeConfig(f, {
    gateway: {
      bind: "loopback",
      port: TEST_PORT,
      auth: { mode: "token", token: placeholder },
    },
  });
  const result = run(f, ["--install-spec", "2026.6.10"]);
  assert.equal(result.status, 1);
  assert.match(result.stdout, /matches a published example placeholder/u);
  assert.doesNotMatch(result.stdout, new RegExp(placeholder, "u"));
});

test("moving install targets are flagged", () => {
  const f = fixture();
  writeConfig(f, {
    gateway: {
      bind: "loopback",
      port: TEST_PORT,
      auth: { mode: "token", token: "0123456789abcdef0123456789abcdef" },
    },
  });
  const result = run(f, ["--install-spec", "latest"]);
  assert.equal(result.status, 0, result.stdout);
  assert.match(result.stdout, /install target latest is moving/u);
  assert.match(
    result.stdout,
    /Summary: No security problems found\. 1 item flagged for your review; exit code 0\./u,
  );
});

test("plain config token wins over the auditor environment", () => {
  const f = fixture();
  writeConfig(f, {
    gateway: {
      bind: "loopback",
      port: TEST_PORT,
      auth: { mode: "token", token: "weak12" },
    },
  });
  const result = run(f, ["--install-spec", "2026.6.10"], {
    OPENCLAW_GATEWAY_TOKEN: "A".repeat(48),
  });
  assert.equal(result.status, 0, result.stdout);
  assert.match(result.stdout, /Gateway authentication: present via config, length 6/u);
  assert.doesNotMatch(result.stdout, /Gateway authentication:.*length 48/u);
});

test("plain config token also wins over the matched Gateway process environment", () => {
  const resolved = resolveGatewayCredential(
    "weak12",
    { gateway: { auth: { mode: "token", token: "weak12" } } },
    [{ env: { OPENCLAW_GATEWAY_TOKEN: "A".repeat(48) } }],
    os.tmpdir(),
    "OPENCLAW_GATEWAY_TOKEN",
  );
  assert.equal(resolved.status, "value");
  assert.equal(resolved.source, "config");
  assert.equal(resolved.value.length, 6);
});

test("all supported string env refs fail closed when unresolved", () => {
  const markers = [
    "$MY_LONG_GATEWAY_TOKEN_ID_123456",
    "secretref-env:MY_LONG_GATEWAY_TOKEN_ID_123456",
    "__env__:MY_LONG_GATEWAY_TOKEN_ID_123456",
  ];
  for (const marker of markers) {
    const f = fixture();
    writeConfig(f, {
      gateway: {
        bind: "loopback",
        port: TEST_PORT,
        auth: { mode: "token", token: marker },
      },
    });
    const result = run(f, ["--install-spec", "2026.6.10"], {
      MY_LONG_GATEWAY_TOKEN_ID_123456: "B".repeat(48),
      OPENCLAW_GATEWAY_TOKEN: "C".repeat(48),
    });
    assert.equal(result.status, 0, result.stdout);
    assert.match(result.stdout, /\[CANNOT CHECK\] Gateway authentication/u);
    assert.doesNotMatch(result.stdout, /\[PASS\] Gateway authentication/u);
  }
});

test("an env ref can use the Gateway bootstrap token from state .env", () => {
  const f = fixture();
  writeConfig(f, {
    gateway: {
      bind: "loopback",
      port: TEST_PORT,
      auth: { mode: "token", token: "$MISSING_DEDICATED_REF" },
    },
  });
  fs.writeFileSync(path.join(f.stateDir, ".env"), `OPENCLAW_GATEWAY_TOKEN=${"D".repeat(32)}\n`, {
    mode: 0o600,
  });
  const result = run(f, ["--install-spec", "2026.6.10"]);
  assert.equal(result.status, 0, result.stdout);
  assert.match(result.stdout, /present via state \.env bootstrap, length 32/u);
});

test("a stopped Gateway can use its systemd environment file token", () => {
  const f = fixture();
  writeConfig(f, {
    gateway: {
      bind: "loopback",
      port: TEST_PORT,
      auth: { mode: "token" },
    },
  });
  fs.writeFileSync(
    path.join(f.stateDir, "gateway.systemd.env"),
    `OPENCLAW_GATEWAY_TOKEN=${"S".repeat(32)}\n`,
    { mode: 0o600 },
  );
  const result = run(f, ["--install-spec", "2026.6.10"]);
  assert.equal(result.status, 0, result.stdout);
  assert.match(result.stdout, /present via gateway\.systemd\.env bootstrap, length 32/u);
});

test("a plain config token wins over gateway.systemd.env", () => {
  const f = fixture();
  writeConfig(f, {
    gateway: {
      bind: "loopback",
      port: TEST_PORT,
      auth: { mode: "token", token: "weak12" },
    },
  });
  fs.writeFileSync(
    path.join(f.stateDir, "gateway.systemd.env"),
    `OPENCLAW_GATEWAY_TOKEN=${"S".repeat(48)}\n`,
    { mode: 0o600 },
  );
  const result = run(f, ["--install-spec", "2026.6.10"]);
  assert.equal(result.status, 0, result.stdout);
  assert.match(result.stdout, /Gateway authentication: present via config, length 6/u);
  assert.doesNotMatch(result.stdout, /Gateway authentication:.*length 48/u);
});

test("a stopped Gateway without a disk token is reported as unverified", () => {
  const f = fixture();
  writeConfig(f, {
    gateway: {
      bind: "loopback",
      port: TEST_PORT,
      auth: { mode: "token" },
    },
  });
  const result = run(f, ["--install-spec", "2026.6.10"]);
  assert.equal(result.status, 0, result.stdout);
  assert.match(
    result.stdout,
    /\[CANNOT CHECK\] Gateway authentication: token auth is selected, but no token was found in config, state \.env, or gateway\.systemd\.env/u,
  );
  assert.doesNotMatch(result.stdout, /no credential is configured/u);
  assert.match(
    result.stdout,
    /Summary: No security problems found\. 1 could not be checked; exit code 0\./u,
  );
});

test("an env ref can use the matched Gateway process bootstrap token", () => {
  const resolved = resolveGatewayCredential(
    "$MISSING_DEDICATED_REF",
    { gateway: { auth: { mode: "token" } } },
    [{ env: { OPENCLAW_GATEWAY_TOKEN: "E".repeat(32) } }],
    os.tmpdir(),
    "OPENCLAW_GATEWAY_TOKEN",
  );
  assert.equal(resolved.status, "value");
  assert.equal(resolved.source, "Gateway process environment bootstrap");
  assert.equal(resolved.value.length, 32);
});

test("a running Gateway with no token still reports a failure", async () => {
  const f = fixture();
  writeConfig(f, {
    gateway: {
      bind: "loopback",
      port: TEST_PORT,
      auth: { mode: "token" },
    },
  });
  const entryFile = path.join(f.directory, "dist", "index.js");
  fs.mkdirSync(path.dirname(entryFile), { recursive: true });
  fs.writeFileSync(entryFile, "setInterval(() => {}, 1000);\n", { mode: 0o600 });
  const gateway = spawn(process.execPath, [entryFile, "gateway", "--port", String(TEST_PORT)], {
    env: {
      HOME: f.home,
      OPENCLAW_CONFIG_PATH: f.configPath,
      OPENCLAW_STATE_DIR: f.stateDir,
      PATH: "",
    },
    stdio: "ignore",
  });
  await new Promise((resolve, reject) => {
    gateway.once("spawn", resolve);
    gateway.once("error", reject);
  });
  try {
    const result = run(f, ["--install-spec", "2026.6.10"]);
    assert.equal(result.status, 1, result.stdout);
    assert.match(
      result.stdout,
      /\[FAIL\] Gateway authentication: token auth is selected, but no token was found in config or the Gateway process environment/u,
    );
  } finally {
    gateway.kill();
    await new Promise((resolve) => gateway.once("close", resolve));
  }
});

test("trusted-proxy auth is gated by its userHeader", () => {
  const valid = fixture();
  writeConfig(valid, {
    gateway: {
      bind: "loopback",
      port: TEST_PORT,
      auth: { mode: "trusted-proxy", trustedProxy: { userHeader: "x-auth-user" } },
    },
  });
  const validResult = run(valid, ["--install-spec", "2026.6.10"]);
  assert.equal(validResult.status, 0, validResult.stdout);
  assert.match(validResult.stdout, /trusted-proxy mode has a non-empty userHeader/u);

  const invalid = fixture();
  writeConfig(invalid, {
    gateway: {
      bind: "loopback",
      port: TEST_PORT,
      auth: { mode: "trusted-proxy", trustedProxy: { userHeader: " " } },
    },
  });
  const invalidResult = run(invalid, ["--install-spec", "2026.6.10"]);
  assert.equal(invalidResult.status, 1);
  assert.match(invalidResult.stdout, /no non-empty gateway\.auth\.trustedProxy\.userHeader/u);
});

test("an unset bind defaults to external auto mode in a container", () => {
  assert.deepEqual(configuredBind({ gateway: {} }, { containerEnvironment: true }), {
    kind: "external",
    detail: "auto -> 0.0.0.0 (container default)",
  });
  assert.equal(
    configuredBind({ gateway: {}, tailscale: { mode: "serve" } }, { containerEnvironment: true })
      .kind,
    "loopback",
  );
  assert.equal(
    detectContainerEnvironment({
      env: {},
      fileExists: (candidate) => candidate === "/.dockerenv",
      readCgroup: () => "0::/",
    }),
    true,
  );
});

test("Gateway argv detection accepts entry files and the dedicated binary", () => {
  assert.equal(isGatewayArgv(["node", "/srv/dist/index.js", "gateway", "--port", "18789"]), true);
  assert.equal(isGatewayArgv(["/usr/local/bin/openclaw-gateway", "gateway"]), true);
  assert.equal(isGatewayArgv(["node", "/srv/worker.js", "gateway"]), false);
});

test("plugin inventory includes dist-runtime and config-directory roots", () => {
  const f = fixture("2026.6.10", { configOutsideState: true });
  writeConfig(f, {
    gateway: {
      bind: "loopback",
      port: TEST_PORT,
      auth: { mode: "token", token: "0123456789abcdef0123456789abcdef" },
    },
  });
  const bundled = path.join(f.packageRoot, "dist-runtime", "extensions", "stock-only");
  const managed = path.join(path.dirname(f.configPath), "extensions", "review-me");
  fs.mkdirSync(bundled, { recursive: true });
  fs.mkdirSync(managed, { recursive: true });
  fs.writeFileSync(
    path.join(bundled, "openclaw.plugin.json"),
    JSON.stringify({ id: "stock-only" }),
  );
  fs.writeFileSync(path.join(managed, "openclaw.plugin.json"), JSON.stringify({ id: "review-me" }));
  const result = run(f, ["--install-spec", "2026.6.10"]);
  assert.equal(result.status, 0, result.stdout);
  assert.match(result.stdout, /Bundled plugins: 1: stock-only/u);
  assert.match(result.stdout, /Third-party plugins: 1: review-me/u);
});

test("WARN and CANNOT CHECK results alone exit 0 with a severity-aware summary", () => {
  const f = fixture();
  writeConfig(f, {
    gateway: {
      bind: "loopback",
      port: TEST_PORT,
      auth: { mode: "token", token: "0123456789abcdef0123456789abcdef" },
    },
  });
  const plugin = path.join(f.stateDir, "extensions", "review-plugin");
  const skill = path.join(f.stateDir, "skills", "review-skill");
  fs.mkdirSync(plugin, { recursive: true });
  fs.mkdirSync(skill, { recursive: true });
  fs.writeFileSync(
    path.join(plugin, "openclaw.plugin.json"),
    JSON.stringify({ id: "review-plugin" }),
  );
  fs.writeFileSync(path.join(skill, "SKILL.md"), "---\nname: review-skill\n---\n");

  const result = run(f);
  assert.equal(result.status, 0, result.stdout);
  assert.match(result.stdout, /\[WARN\] Third-party plugins:/u);
  assert.match(result.stdout, /\[WARN\] Third-party skills:/u);
  assert.match(result.stdout, /\[CANNOT CHECK\] Installation pin:/u);
  assert.match(
    result.stdout,
    /Summary: No security problems found\. 2 items flagged for your review, 1 could not be checked; exit code 0\./u,
  );
});

test("a FAIL exits 1 with a security-problem summary", () => {
  const f = fixture();
  writeConfig(f, {
    gateway: {
      bind: "lan",
      port: TEST_PORT,
      auth: {
        mode: "token",
        token: "0123456789abcdef0123456789abcdef",
        rateLimit: {},
      },
    },
  });
  const result = run(f, ["--install-spec", "2026.6.10"]);
  assert.equal(result.status, 1, result.stdout);
  assert.equal(result.stdout.match(/^\[FAIL\]/gmu)?.length, 1, result.stdout);
  assert.match(result.stdout, /Summary: 1 problem needs attention; exit code 1\./u);
});

test("canary secrets never appear through config, env-file, ref, or password branches", () => {
  const cases = [
    {
      name: "config token",
      auth: (secret) => ({ mode: "token", token: secret }),
    },
    {
      name: "environment token",
      auth: () => ({ mode: "token" }),
      envLine: (secret) => `OPENCLAW_GATEWAY_TOKEN=${secret}\n`,
    },
    {
      name: "environment ref",
      auth: () => ({ mode: "token", token: "$CANARY_GATEWAY_REF" }),
      envLine: (secret) => `CANARY_GATEWAY_REF=${secret}\n`,
    },
    {
      name: "systemd environment token",
      auth: () => ({ mode: "token" }),
      envFile: "gateway.systemd.env",
      envLine: (secret) => `OPENCLAW_GATEWAY_TOKEN=${secret}\n`,
    },
    {
      name: "config password",
      auth: (secret) => ({ mode: "password", password: secret }),
    },
  ];
  for (const [index, entry] of cases.entries()) {
    const f = fixture();
    const secret = `CANARY_${index}_${"Z".repeat(32)}`;
    writeConfig(f, {
      gateway: { bind: "loopback", port: TEST_PORT, auth: entry.auth(secret) },
    });
    if (entry.envLine) {
      fs.writeFileSync(path.join(f.stateDir, entry.envFile ?? ".env"), entry.envLine(secret), {
        mode: 0o600,
      });
    }
    const result = run(f, ["--install-spec", "2026.6.10"]);
    assert.equal(result.status, 0, `${entry.name}\n${result.stdout}`);
    assert.doesNotMatch(`${result.stdout}${result.stderr}`, new RegExp(secret, "u"));
    assert.match(result.stdout, new RegExp(`length ${secret.length}`, "u"));
  }
});

test("the script contains no network, process-launch, or write API calls", () => {
  const source = fs.readFileSync(script, "utf8");
  assert.doesNotMatch(
    source,
    /fetch|http|https\.request|net\.connect|child_process|exec|spawn|writeFile/iu,
  );
  assert.doesNotMatch(source, /node:(?:http|https|net|tls|dns|dgram)/u);
});

test("the script is syntactically valid", () => {
  execFileSync(process.execPath, ["--check", script], { stdio: "pipe" });
});

test("invalid command-line options are explained and exit 2", () => {
  const result = spawnSync(process.execPath, [script, "--bogus"], {
    encoding: "utf8",
    env: { HOME: os.tmpdir(), PATH: "" },
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Unknown option: --bogus/u);
});
