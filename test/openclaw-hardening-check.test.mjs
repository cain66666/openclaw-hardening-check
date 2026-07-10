import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const script = path.join(root, "openclaw-hardening-check.mjs");

function fixture(version = "2026.6.10") {
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
    configPath: path.join(stateDir, "openclaw.json"),
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
        port: 18789,
        auth: { mode: 'token', token: '0123456789abcdef0123456789abcdef', },
      },
    }`,
  );
  const result = run(f, ["--install-spec", "2026.6.10"]);
  assert.equal(result.status, 0, result.stdout);
  assert.match(result.stdout, /installed package version 2026\.6\.10 is at or newer/u);
  assert.match(result.stdout, /exact target 2026\.6\.10/u);
});

test("versions before 2026.1.29 are reported as affected", () => {
  const f = fixture("2026.1.28");
  writeConfig(f, {
    gateway: {
      bind: "loopback",
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
      auth: { mode: "token", token: "0123456789abcdef0123456789abcdef" },
    },
  });
  const result = run(f, ["--install-spec", "latest"]);
  assert.equal(result.status, 1);
  assert.match(result.stdout, /install target latest is moving/u);
});

test("the script contains no network API calls", () => {
  const source = fs.readFileSync(script, "utf8");
  assert.doesNotMatch(source, /fetch|http|https\.request|net\.connect/iu);
  assert.doesNotMatch(source, /node:(?:http|https|net|tls|dns|dgram)/u);
});

test("the script is syntactically valid", () => {
  execFileSync(process.execPath, ["--check", script], { stdio: "pipe" });
});
