#!/usr/bin/env node

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const FIXED_VERSION = "2026.1.29";
const DEFAULT_GATEWAY_PORT = 18789;
const MAX_CONFIG_BYTES = 2 * 1024 * 1024;
const MAX_INCLUDE_DEPTH = 10;
const MAX_INVENTORY_ITEMS = 1000;
const SYSTEMD_GATEWAY_ENV_FILENAME = "gateway.systemd.env";
const KNOWN_WEAK_TOKENS = new Set(["change-me-to-a-long-random-token", "change-me-now"]);
const KNOWN_WEAK_PASSWORDS = new Set(["change-me-to-a-strong-password"]);

class SafeError extends Error {
  constructor(message, code = undefined) {
    super(message);
    this.name = "SafeError";
    this.code = code;
  }
}

class Json5Parser {
  constructor(input) {
    this.input = input.replace(/^\uFEFF/u, "");
    this.index = 0;
  }

  parse() {
    const value = this.parseValue();
    this.skipTrivia();
    if (this.index !== this.input.length) this.fail();
    return value;
  }

  fail() {
    const before = this.input.slice(0, this.index);
    const line = before.split("\n").length;
    const lastNewline = before.lastIndexOf("\n");
    const column = this.index - lastNewline;
    throw new SafeError(`Config syntax error at line ${line}, column ${column}.`, "EPARSE");
  }

  skipTrivia() {
    while (this.index < this.input.length) {
      const char = this.input[this.index];
      if (/\s/u.test(char)) {
        this.index += 1;
        continue;
      }
      if (char === "/" && this.input[this.index + 1] === "/") {
        this.index += 2;
        while (this.index < this.input.length && this.input[this.index] !== "\n") {
          this.index += 1;
        }
        continue;
      }
      if (char === "/" && this.input[this.index + 1] === "*") {
        const end = this.input.indexOf("*/", this.index + 2);
        if (end === -1) this.fail();
        this.index = end + 2;
        continue;
      }
      break;
    }
  }

  parseValue() {
    this.skipTrivia();
    const char = this.input[this.index];
    if (char === "{") return this.parseObject();
    if (char === "[") return this.parseArray();
    if (char === '"' || char === "'") return this.parseString();
    if (char === "+" || char === "-" || char === "." || /[0-9]/u.test(char ?? "")) {
      return this.parseNumber();
    }
    if (this.isIdentifierStart(char)) {
      const identifier = this.parseIdentifier();
      if (identifier === "true") return true;
      if (identifier === "false") return false;
      if (identifier === "null") return null;
      if (identifier === "Infinity") return Infinity;
      if (identifier === "NaN") return NaN;
    }
    this.fail();
  }

  parseObject() {
    const result = Object.create(null);
    this.index += 1;
    this.skipTrivia();
    if (this.input[this.index] === "}") {
      this.index += 1;
      return result;
    }
    while (this.index < this.input.length) {
      this.skipTrivia();
      let key;
      const char = this.input[this.index];
      if (char === '"' || char === "'") {
        key = this.parseString();
      } else if (this.isIdentifierStart(char)) {
        key = this.parseIdentifier();
      } else if (char === "+" || char === "-" || char === "." || /[0-9]/u.test(char ?? "")) {
        key = String(this.parseNumber());
      } else {
        this.fail();
      }
      this.skipTrivia();
      if (this.input[this.index] !== ":") this.fail();
      this.index += 1;
      const value = this.parseValue();
      if (key !== "__proto__" && key !== "prototype" && key !== "constructor") {
        result[key] = value;
      }
      this.skipTrivia();
      const separator = this.input[this.index];
      if (separator === "}") {
        this.index += 1;
        return result;
      }
      if (separator !== ",") this.fail();
      this.index += 1;
      this.skipTrivia();
      if (this.input[this.index] === "}") {
        this.index += 1;
        return result;
      }
    }
    this.fail();
  }

  parseArray() {
    const result = [];
    this.index += 1;
    this.skipTrivia();
    if (this.input[this.index] === "]") {
      this.index += 1;
      return result;
    }
    while (this.index < this.input.length) {
      result.push(this.parseValue());
      this.skipTrivia();
      const separator = this.input[this.index];
      if (separator === "]") {
        this.index += 1;
        return result;
      }
      if (separator !== ",") this.fail();
      this.index += 1;
      this.skipTrivia();
      if (this.input[this.index] === "]") {
        this.index += 1;
        return result;
      }
    }
    this.fail();
  }

  parseString() {
    const quote = this.input[this.index];
    let result = "";
    this.index += 1;
    while (this.index < this.input.length) {
      const char = this.input[this.index];
      this.index += 1;
      if (char === quote) return result;
      if (char === "\n" || char === "\r") this.fail();
      if (char !== "\\") {
        result += char;
        continue;
      }
      if (this.index >= this.input.length) this.fail();
      const escape = this.input[this.index];
      this.index += 1;
      const simple = {
        b: "\b",
        f: "\f",
        n: "\n",
        r: "\r",
        t: "\t",
        v: "\v",
        0: "\0",
        "\\": "\\",
        "'": "'",
        '"': '"',
      };
      if (escape in simple) {
        result += simple[escape];
      } else if (escape === "x") {
        const hex = this.input.slice(this.index, this.index + 2);
        if (!/^[0-9a-f]{2}$/iu.test(hex)) this.fail();
        result += String.fromCharCode(Number.parseInt(hex, 16));
        this.index += 2;
      } else if (escape === "u") {
        const hex = this.input.slice(this.index, this.index + 4);
        if (!/^[0-9a-f]{4}$/iu.test(hex)) this.fail();
        result += String.fromCharCode(Number.parseInt(hex, 16));
        this.index += 4;
      } else if (escape === "\r" || escape === "\n") {
        if (escape === "\r" && this.input[this.index] === "\n") this.index += 1;
      } else {
        result += escape;
      }
    }
    this.fail();
  }

  parseNumber() {
    const rest = this.input.slice(this.index);
    const match = rest.match(
      /^[+-]?(?:Infinity|NaN|0[xX][0-9a-f]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)/iu,
    );
    if (!match) this.fail();
    this.index += match[0].length;
    const raw = match[0];
    if (/^[+-]?Infinity$/u.test(raw)) return raw.startsWith("-") ? -Infinity : Infinity;
    if (/^[+-]?NaN$/u.test(raw)) return NaN;
    const sign = raw.startsWith("-") ? -1 : 1;
    const unsigned = raw.replace(/^[+-]/u, "");
    if (/^0x/iu.test(unsigned)) return sign * Number.parseInt(unsigned.slice(2), 16);
    const value = Number(raw);
    if (Number.isNaN(value)) this.fail();
    return value;
  }

  parseIdentifier() {
    const start = this.index;
    this.index += 1;
    while (this.isIdentifierPart(this.input[this.index])) this.index += 1;
    return this.input.slice(start, this.index);
  }

  isIdentifierStart(char) {
    return typeof char === "string" && /[A-Z_$\p{L}]/iu.test(char);
  }

  isIdentifierPart(char) {
    return typeof char === "string" && /[A-Z0-9_$\p{L}\p{N}]/iu.test(char);
  }
}

function parseJson5(raw) {
  return new Json5Parser(raw).parse();
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function deepMerge(target, source) {
  if (Array.isArray(target) && Array.isArray(source)) return [...target, ...source];
  if (!isObject(target) || !isObject(source)) return source;
  const result = Object.assign(Object.create(null), target);
  for (const [key, value] of Object.entries(source)) {
    if (key === "__proto__" || key === "prototype" || key === "constructor") continue;
    result[key] = key in result ? deepMerge(result[key], value) : value;
  }
  return result;
}

function readLimited(filePath, limit = MAX_CONFIG_BYTES) {
  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch (error) {
    throw new SafeError(
      `Could not read ${displayPath(filePath)} (${error.code ?? "read error"}).`,
      error.code,
    );
  }
  if (!stat.isFile())
    throw new SafeError(`${displayPath(filePath)} is not a regular file.`, "ENOTFILE");
  if (stat.size > limit)
    throw new SafeError(`${displayPath(filePath)} is larger than ${limit} bytes.`, "ETOOBIG");
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch (error) {
    throw new SafeError(
      `Could not read ${displayPath(filePath)} (${error.code ?? "read error"}).`,
      error.code,
    );
  }
}

function isInside(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== "..");
}

function loadConfigWithIncludes(configPath) {
  const loadedFiles = new Set();
  let realConfigPath;
  try {
    realConfigPath = fs.realpathSync(configPath);
  } catch (error) {
    throw new SafeError(
      `Could not read ${displayPath(configPath)} (${error.code ?? "read error"}).`,
      error.code,
    );
  }
  const rootDir = fs.realpathSync(path.dirname(realConfigPath));
  const allowedRoots = [rootDir];
  const extraRoots = String(process.env.OPENCLAW_INCLUDE_ROOTS ?? "")
    .split(path.delimiter)
    .map((entry) => entry.trim())
    .filter(Boolean);
  for (const entry of extraRoots) {
    if (!path.isAbsolute(entry)) continue;
    try {
      allowedRoots.push(fs.realpathSync(entry));
    } catch {
      // OpenClaw will also reject an unavailable include root when it is used.
    }
  }

  function load(filePath, depth, chain) {
    if (depth > MAX_INCLUDE_DEPTH)
      throw new SafeError("Config include depth exceeds 10.", "EINCLUDE");
    let real;
    try {
      real = fs.realpathSync(filePath);
    } catch (error) {
      throw new SafeError(
        `Could not read a config include (${error.code ?? "read error"}).`,
        error.code,
      );
    }
    if (!allowedRoots.some((root) => isInside(real, root))) {
      throw new SafeError(
        "A config include resolves outside the allowed config roots.",
        "EINCLUDE",
      );
    }
    if (chain.has(real)) throw new SafeError("Circular config include detected.", "EINCLUDE");
    loadedFiles.add(real);
    const parsed = parseJson5(readLimited(real));
    return resolveNode(parsed, real, depth, new Set([...chain, real]));
  }

  function resolveNode(value, baseFile, depth, chain) {
    if (Array.isArray(value))
      return value.map((entry) => resolveNode(entry, baseFile, depth, chain));
    if (!isObject(value)) return value;
    if (!("$include" in value)) {
      const result = Object.create(null);
      for (const [key, entry] of Object.entries(value)) {
        result[key] = resolveNode(entry, baseFile, depth, chain);
      }
      return result;
    }
    const includeValue = value.$include;
    const entries = typeof includeValue === "string" ? [includeValue] : includeValue;
    if (!Array.isArray(entries) || entries.some((entry) => typeof entry !== "string")) {
      throw new SafeError("Invalid $include value in config.", "EINCLUDE");
    }
    let included = Object.create(null);
    for (const entry of entries) {
      if (entry.length === 0 || entry.length >= 4096 || entry.includes("\0")) {
        throw new SafeError("Invalid config include path.", "EINCLUDE");
      }
      const resolved = path.isAbsolute(entry)
        ? path.normalize(entry)
        : path.resolve(path.dirname(baseFile), entry);
      included = deepMerge(included, load(resolved, depth + 1, chain));
    }
    const siblings = Object.create(null);
    for (const [key, entry] of Object.entries(value)) {
      if (key !== "$include") siblings[key] = resolveNode(entry, baseFile, depth, chain);
    }
    if (Object.keys(siblings).length === 0) return included;
    if (!isObject(included))
      throw new SafeError("Config include siblings require an object.", "EINCLUDE");
    return deepMerge(included, siblings);
  }

  const config = load(realConfigPath, 0, new Set());
  if (!isObject(config)) throw new SafeError("The config root is not an object.", "EPARSE");
  return { config, loadedFiles: [...loadedFiles] };
}

function parseArgs(argv) {
  const options = {
    configPath: undefined,
    stateDir: undefined,
    packageRoot: undefined,
    installSpec: undefined,
    help: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--help" || arg === "-h") {
      options.help = true;
      continue;
    }
    const fields = new Map([
      ["--config", "configPath"],
      ["--state-dir", "stateDir"],
      ["--package-root", "packageRoot"],
      ["--install-spec", "installSpec"],
    ]);
    if (fields.has(arg)) {
      const value = argv[index + 1];
      if (!value || value.startsWith("--"))
        throw new SafeError(`${arg} requires a value.`, "EARGS");
      options[fields.get(arg)] = value;
      index += 1;
      continue;
    }
    throw new SafeError(`Unknown option: ${sanitize(arg)}`, "EARGS");
  }
  return options;
}

function usage() {
  return `Usage: node openclaw-hardening-check.mjs [options]

Options:
  --config PATH         OpenClaw config path
  --state-dir PATH      OpenClaw state directory
  --package-root PATH   Installed OpenClaw package root
  --install-spec SPEC   Original install target, for example 2026.6.10 or latest
  --help                Show this help

The check is read-only, makes no network requests, and never prints secret values.`;
}

let displayHome = os.homedir();

function displayPath(filePath) {
  const absolute = path.resolve(filePath);
  if (absolute === displayHome) return "~";
  if (absolute.startsWith(`${displayHome}${path.sep}`))
    return `~${absolute.slice(displayHome.length)}`;
  return sanitize(absolute);
}

function sanitize(value) {
  return String(value)
    .replace(/[\u0000-\u001F\u007F-\u009F\u2028\u2029]/gu, "?")
    .slice(0, 240);
}

function expandLocalPath(value, home) {
  if (typeof value !== "string" || value.length === 0 || value.includes("${")) return null;
  if (value === "~") return home;
  if (value.startsWith(`~${path.sep}`)) return path.join(home, value.slice(2));
  return path.resolve(value);
}

function resolvePaths(options) {
  const home = os.homedir();
  displayHome = home;
  const stateDir = path.resolve(
    options.stateDir ?? process.env.OPENCLAW_STATE_DIR?.trim() ?? path.join(home, ".openclaw"),
  );
  const configPath = path.resolve(
    options.configPath ??
      process.env.OPENCLAW_CONFIG_PATH?.trim() ??
      path.join(stateDir, "openclaw.json"),
  );
  return { home, stateDir, configPath };
}

class Reporter {
  constructor() {
    this.failures = 0;
    this.warnings = 0;
    this.unknowns = 0;
  }

  pass(label, detail) {
    console.log(`[PASS] ${label}: ${detail}`);
  }

  info(label, detail) {
    console.log(`[INFO] ${label}: ${detail}`);
  }

  warn(label, detail) {
    this.warnings += 1;
    console.log(`[WARN] ${label}: ${detail}`);
  }

  fail(label, detail) {
    this.failures += 1;
    console.log(`[FAIL] ${label}: ${detail}`);
  }

  unknown(label, detail) {
    this.unknowns += 1;
    console.log(`[CANNOT CHECK] ${label}: ${detail}`);
  }
}

function printSummary(reporter) {
  const reviewNote =
    reporter.warnings > 0
      ? `${reporter.warnings} item${reporter.warnings === 1 ? "" : "s"} flagged for your review`
      : null;
  const unknownNote = reporter.unknowns > 0 ? `${reporter.unknowns} could not be checked` : null;
  const secondaryNotes = [reviewNote, unknownNote].filter(Boolean);
  if (reporter.failures === 0) {
    const detail =
      secondaryNotes.length > 0
        ? `No security problems found. ${secondaryNotes.join(", ")}`
        : "No security problems found";
    console.log(`Summary: ${detail}; exit code 0.`);
    return 0;
  }
  const problems = `${reporter.failures} problem${reporter.failures === 1 ? "" : "s"} ${reporter.failures === 1 ? "needs" : "need"} attention`;
  console.log(`Summary: ${[problems, ...secondaryNotes].join(", ")}; exit code 1.`);
  return 1;
}

function formatMode(mode) {
  return (mode & 0o777).toString(8).padStart(3, "0");
}

function checkFilePermission(filePath, reporter, label = "Secret file permissions") {
  if (process.platform === "win32") {
    reporter.unknown(
      label,
      `${displayPath(filePath)}: POSIX mode bits are unavailable on Windows.`,
    );
    return;
  }
  try {
    const stat = fs.statSync(filePath);
    const exposed = stat.mode & 0o077;
    const wrongOwner = typeof process.getuid === "function" && stat.uid !== process.getuid();
    if ((exposed & 0o066) !== 0 || wrongOwner) {
      const ownerNote = wrongOwner ? "; owned by another user" : "";
      reporter.fail(
        label,
        `${displayPath(filePath)} has mode ${formatMode(stat.mode)}${ownerNote}.`,
      );
    } else {
      reporter.pass(label, `${displayPath(filePath)} has mode ${formatMode(stat.mode)}.`);
    }
  } catch (error) {
    reporter.unknown(label, `${displayPath(filePath)} (${error.code ?? "stat error"}).`);
  }
}

function readDotEnvSecret(filePath, key) {
  if (!fs.existsSync(filePath)) return undefined;
  let raw;
  try {
    raw = readLimited(filePath, 1024 * 1024);
  } catch {
    return undefined;
  }
  let found;
  for (const line of raw.split(/\r?\n/u)) {
    const match = line.match(/^\s*(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*=\s*(.*)$/u);
    if (!match || match[1] !== key) continue;
    let value = match[2].trim();
    if (
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'")))
    ) {
      value = value.slice(1, -1);
    } else {
      value = value.replace(/\s+#.*$/u, "").trim();
    }
    found = value;
  }
  return found;
}

function readProcessEnv(pid) {
  const result = Object.create(null);
  try {
    const raw = fs.readFileSync(`/proc/${pid}/environ`);
    for (const entry of raw.toString().split("\0")) {
      const equals = entry.indexOf("=");
      if (equals <= 0) continue;
      const key = entry.slice(0, equals);
      result[key] = entry.slice(equals + 1);
    }
  } catch {
    return null;
  }
  return result;
}

function normalizeProcArg(arg) {
  return String(arg).replaceAll("\\", "/").trim().toLowerCase();
}

function isGatewayArgv(args, { allowGatewayBinary = true } = {}) {
  const normalized = args.map(normalizeProcArg);
  if (!normalized.includes("gateway")) return false;
  const entryCandidates = [
    "dist/index.js",
    "dist/entry.js",
    "openclaw.mjs",
    "scripts/run-node.mjs",
    "src/entry.ts",
    "src/index.ts",
  ];
  if (normalized.some((arg) => entryCandidates.some((entry) => arg.endsWith(entry)))) return true;
  const binary = (normalized[0] ?? "").replace(/\.(bat|cmd|exe)$/iu, "");
  return (
    binary.endsWith("/openclaw") ||
    binary === "openclaw" ||
    (allowGatewayBinary && binary.endsWith("/openclaw-gateway"))
  );
}

function findGatewayProcesses(configPath, stateDir) {
  if (process.platform !== "linux" || !fs.existsSync("/proc")) {
    return { supported: false, processes: [] };
  }
  const processes = [];
  let names;
  try {
    names = fs.readdirSync("/proc");
  } catch {
    return { supported: false, processes: [] };
  }
  for (const name of names) {
    if (!/^\d+$/u.test(name) || Number(name) === process.pid) continue;
    let argv;
    try {
      argv = fs.readFileSync(`/proc/${name}/cmdline`).toString().split("\0").filter(Boolean);
    } catch {
      continue;
    }
    if (!isGatewayArgv(argv)) continue;
    const env = readProcessEnv(name);
    if (env) {
      const processConfig = env.OPENCLAW_CONFIG_PATH
        ? path.resolve(env.OPENCLAW_CONFIG_PATH)
        : path.join(path.resolve(env.OPENCLAW_STATE_DIR ?? stateDir), "openclaw.json");
      if (processConfig !== configPath) continue;
    }
    let argPort;
    const portIndex = argv.findIndex((arg) => arg === "--port");
    if (portIndex !== -1 && /^\d+$/u.test(argv[portIndex + 1] ?? "")) {
      argPort = Number(argv[portIndex + 1]);
    }
    processes.push({ pid: Number(name), env, argPort });
  }
  return { supported: true, processes };
}

function resolveGatewayPort(config, processes) {
  for (const processInfo of processes) {
    if (processInfo.argPort) return processInfo.argPort;
    const envPort = processInfo.env?.OPENCLAW_GATEWAY_PORT;
    if (/^\d+$/u.test(envPort ?? "")) return Number(envPort);
  }
  const configPort = config.gateway?.port;
  if (Number.isInteger(configPort) && configPort > 0 && configPort <= 65535) return configPort;
  return DEFAULT_GATEWAY_PORT;
}

function decodeIpv4(hex) {
  const bytes =
    hex
      .match(/../gu)
      ?.map((entry) => Number.parseInt(entry, 16))
      .reverse() ?? [];
  return bytes.join(".");
}

function decodeIpv6(hex) {
  const bytes = [];
  for (let offset = 0; offset < 32; offset += 8) {
    const word =
      hex
        .slice(offset, offset + 8)
        .match(/../gu)
        ?.reverse() ?? [];
    bytes.push(...word);
  }
  const groups = [];
  for (let offset = 0; offset < 16; offset += 2) {
    groups.push(Number.parseInt(`${bytes[offset]}${bytes[offset + 1]}`, 16).toString(16));
  }
  const joined = groups.join(":");
  return joined === "0:0:0:0:0:0:0:0" ? "::" : joined === "0:0:0:0:0:0:0:1" ? "::1" : joined;
}

function parseProcListeners(filePath, ipv6) {
  let raw;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch {
    return [];
  }
  const listeners = [];
  for (const line of raw.trim().split("\n").slice(1)) {
    const fields = line.trim().split(/\s+/u);
    if (fields.length < 10 || fields[3] !== "0A") continue;
    const [addressHex, portHex] = fields[1].split(":");
    listeners.push({
      address: ipv6 ? decodeIpv6(addressHex) : decodeIpv4(addressHex),
      port: Number.parseInt(portHex, 16),
      inode: fields[9],
      ipv6,
    });
  }
  return listeners;
}

function socketInodesForPid(pid) {
  const inodes = new Set();
  let entries;
  try {
    entries = fs.readdirSync(`/proc/${pid}/fd`);
  } catch {
    return null;
  }
  for (const entry of entries) {
    try {
      const target = fs.readlinkSync(`/proc/${pid}/fd/${entry}`);
      const match = target.match(/^socket:\[(\d+)\]$/u);
      if (match) inodes.add(match[1]);
    } catch {
      // File descriptors can disappear while they are inspected.
    }
  }
  return inodes;
}

function isLoopbackAddress(address) {
  return address === "::1" || address.startsWith("127.");
}

function detectContainerEnvironment({
  env = process.env,
  fileExists = fs.existsSync,
  readCgroup = () => fs.readFileSync("/proc/1/cgroup", "utf8"),
} = {}) {
  if (env.FLY_MACHINE_ID?.trim() && env.FLY_APP_NAME?.trim()) return true;
  for (const sentinel of ["/.dockerenv", "/run/.containerenv", "/var/run/.containerenv"]) {
    try {
      if (fileExists(sentinel)) return true;
    } catch {
      // Try the next local signal.
    }
  }
  try {
    return /\/docker\/|cri-containerd-[0-9a-f]|containerd\/[0-9a-f]{64}|\/kubepods[/.]|\blxc\b/u.test(
      readCgroup(),
    );
  } catch {
    return false;
  }
}

function checkRuntimeSockets(processDiscovery, expectedPort, reporter) {
  if (!processDiscovery.supported) {
    reporter.unknown(
      "Listening sockets",
      "Linux /proc socket inspection is unavailable on this platform.",
    );
    return;
  }
  const systemListeners = [
    ...parseProcListeners("/proc/net/tcp", false),
    ...parseProcListeners("/proc/net/tcp6", true),
  ];
  if (processDiscovery.processes.length === 0) {
    if (systemListeners.some((entry) => entry.port === expectedPort)) {
      reporter.unknown(
        "Listening sockets",
        `TCP port ${expectedPort} is listening, but its owner was not verified as the selected OpenClaw Gateway.`,
      );
      return;
    }
    reporter.info(
      "Listening sockets",
      "OpenClaw Gateway is not running; disk checks still completed.",
    );
    return;
  }
  const ownedInodes = new Set();
  for (const processInfo of processDiscovery.processes) {
    const inodes = socketInodesForPid(processInfo.pid);
    if (inodes === null) {
      reporter.unknown(
        "Listening sockets",
        "Could not inspect the running Gateway file descriptors.",
      );
      return;
    }
    for (const inode of inodes) ownedInodes.add(inode);
  }
  const listeners = systemListeners.filter((entry) => ownedInodes.has(entry.inode));
  if (listeners.length === 0) {
    reporter.unknown(
      "Listening sockets",
      "The Gateway is running but no owned TCP listener could be identified.",
    );
    return;
  }
  const external = listeners.filter((entry) => !isLoopbackAddress(entry.address));
  const rendered = listeners
    .map((entry) => `${entry.ipv6 ? `[${entry.address}]` : entry.address}:${entry.port}`)
    .sort()
    .join(", ");
  if (external.length > 0) {
    reporter.fail(
      "Listening sockets",
      `OpenClaw owns non-loopback TCP listeners: ${sanitize(rendered)}.`,
    );
  } else {
    const portNote = listeners.some((entry) => entry.port === expectedPort)
      ? ""
      : ` Expected Gateway port ${expectedPort} was not among them.`;
    reporter.pass(
      "Listening sockets",
      `OpenClaw TCP listeners are loopback-only: ${sanitize(rendered)}.${portNote}`,
    );
  }
}

function configuredBind(config, { containerEnvironment = detectContainerEnvironment() } = {}) {
  const bind = config.gateway?.bind;
  const tailscaleMode = config.gateway?.tailscale?.mode ?? config.tailscale?.mode;
  if (bind === undefined) {
    if (tailscaleMode && tailscaleMode !== "off") {
      return {
        kind: "loopback",
        detail: `loopback (default for Tailscale ${sanitize(tailscaleMode)})`,
      };
    }
    if (containerEnvironment) {
      return { kind: "external", detail: "auto -> 0.0.0.0 (container default)" };
    }
    return { kind: "loopback", detail: "loopback (default)" };
  }
  if (typeof bind !== "string") return { kind: "unknown", detail: "gateway.bind is not a string" };
  const normalized = bind.trim().toLowerCase();
  if (["loopback", "127.0.0.1", "localhost", "::1"].includes(normalized)) {
    return { kind: "loopback", detail: normalized };
  }
  if (normalized === "custom") {
    const host = config.gateway?.customBindHost;
    if (typeof host !== "string" || host.trim() === "") {
      return { kind: "unknown", detail: "custom bind has no customBindHost" };
    }
    return isLoopbackAddress(host.trim()) || host.trim().toLowerCase() === "localhost"
      ? { kind: "loopback", detail: `custom (${sanitize(host.trim())})` }
      : { kind: "external", detail: `custom (${sanitize(host.trim())})` };
  }
  if (["lan", "0.0.0.0", "::", "tailnet"].includes(normalized)) {
    return { kind: "external", detail: normalized };
  }
  if (normalized === "auto" && containerEnvironment) {
    return { kind: "external", detail: "auto -> 0.0.0.0 (container)" };
  }
  if (normalized === "auto") return { kind: "unknown", detail: "auto (runtime-dependent)" };
  return { kind: "unknown", detail: sanitize(normalized) };
}

function checkBind(config, reporter) {
  const bind = configuredBind(config);
  if (bind.kind === "loopback")
    reporter.pass("Gateway bind", `${bind.detail}; configured for local-only access.`);
  else if (bind.kind === "external")
    reporter.fail("Gateway bind", `${bind.detail}; configured on a non-loopback interface.`);
  else reporter.unknown("Gateway bind", `${bind.detail}.`);
  const tailscaleMode = config.gateway?.tailscale?.mode ?? config.tailscale?.mode;
  if (tailscaleMode === "funnel")
    reporter.fail("Tailscale exposure", "Funnel mode can publish the Gateway externally.");
  else if (tailscaleMode === "serve")
    reporter.info("Tailscale exposure", "Serve mode is enabled for tailnet access.");
  return bind;
}

function parseSecretReference(value) {
  if (typeof value === "string") {
    const trimmed = value.trim();
    const envMarker =
      trimmed.match(/^\$\{([A-Z][A-Z0-9_]{0,127})\}$/u) ??
      trimmed.match(/^\$([A-Z][A-Z0-9_]{0,127})$/u) ??
      trimmed.match(/^(?:secretref-env:|__env__:)([A-Z][A-Z0-9_]{0,127})$/u);
    return envMarker ? { source: "env", provider: "default", id: envMarker[1] } : null;
  }
  if (!isObject(value)) return null;
  if (
    typeof value.source === "string" &&
    value.source.trim().length > 0 &&
    typeof value.id === "string" &&
    value.id.trim().length > 0
  ) {
    return {
      source: value.source,
      provider:
        typeof value.provider === "string" && value.provider.trim()
          ? value.provider.trim()
          : "default",
      id: value.id.trim(),
    };
  }
  return null;
}

function gatewayEnvironment(processes) {
  const environment = Object.create(null);
  const conflicts = new Set();
  for (const processInfo of processes) {
    if (!processInfo.env) continue;
    for (const [key, value] of Object.entries(processInfo.env)) {
      if (conflicts.has(key)) continue;
      if (Object.hasOwn(environment, key) && environment[key] !== value) {
        delete environment[key];
        conflicts.add(key);
      } else {
        environment[key] = value;
      }
    }
  }
  return environment;
}

function nonEmptyEnvironmentValue(value, source) {
  return typeof value === "string" && value.trim().length > 0
    ? { status: "value", value, source }
    : null;
}

function resolveKnownEnvironment(refId, envKey, environment, stateDir, allowStateEnv) {
  const envFile = path.join(stateDir, ".env");
  const systemdEnvFile = path.join(stateDir, SYSTEMD_GATEWAY_ENV_FILENAME);
  const candidates = [];
  if (refId) {
    candidates.push(
      nonEmptyEnvironmentValue(environment[refId], "Gateway process environment ref"),
    );
    if (allowStateEnv) {
      candidates.push(
        nonEmptyEnvironmentValue(
          readDotEnvSecret(systemdEnvFile, refId),
          "gateway.systemd.env ref",
        ),
        nonEmptyEnvironmentValue(readDotEnvSecret(envFile, refId), "state .env ref"),
      );
    }
  }
  candidates.push(
    nonEmptyEnvironmentValue(environment[envKey], "Gateway process environment bootstrap"),
  );
  if (allowStateEnv) {
    candidates.push(
      nonEmptyEnvironmentValue(
        readDotEnvSecret(systemdEnvFile, envKey),
        "gateway.systemd.env bootstrap",
      ),
      nonEmptyEnvironmentValue(readDotEnvSecret(envFile, envKey), "state .env bootstrap"),
    );
  }
  return candidates.find(Boolean) ?? null;
}

function resolveSecretReference(ref, config, environment, stateDir, envKey, allowStateEnv) {
  if (ref.source === "env") {
    return (
      resolveKnownEnvironment(ref.id, envKey, environment, stateDir, allowStateEnv) ?? {
        status: "unknown",
        source: "environment SecretRef",
      }
    );
  }
  if (ref.source === "file") {
    const provider = config.secrets?.providers?.[ref.provider];
    const providerPath = expandLocalPath(provider?.path, os.homedir());
    if (providerPath) {
      try {
        const parsed = parseJson5(readLimited(providerPath, 1024 * 1024));
        if (isObject(parsed) && typeof parsed[ref.id] === "string") {
          return {
            status: "value",
            value: parsed[ref.id],
            source: "file SecretRef",
            filePath: providerPath,
          };
        }
      } catch {
        // Bootstrap environment fallback remains available below.
      }
    }
    return (
      resolveKnownEnvironment(null, envKey, environment, stateDir, allowStateEnv) ?? {
        status: "unknown",
        source: "file SecretRef",
        ...(providerPath ? { filePath: providerPath } : {}),
      }
    );
  }
  return (
    resolveKnownEnvironment(null, envKey, environment, stateDir, allowStateEnv) ?? {
      status: "unknown",
      source: `${sanitize(ref.source)} SecretRef`,
    }
  );
}

function resolveGatewayCredential(configValue, config, processes, stateDir, envKey) {
  const environment = gatewayEnvironment(processes);
  const allowStateEnv = processes.length === 0;
  const ref = parseSecretReference(configValue);
  if (ref) {
    return resolveSecretReference(ref, config, environment, stateDir, envKey, allowStateEnv);
  }
  if (typeof configValue === "string" && configValue.trim().length > 0) {
    return { status: "value", value: configValue, source: "config" };
  }
  if (configValue !== undefined && configValue !== null && typeof configValue !== "string") {
    return { status: "unknown", source: "unrecognized config credential" };
  }
  return (
    resolveKnownEnvironment(null, envKey, environment, stateDir, allowStateEnv) ?? {
      status: "absent",
      source: "known sources",
    }
  );
}

function checkOneSecret({
  label,
  mode,
  configValue,
  envKey,
  weakValues,
  config,
  processes,
  stateDir,
  reporter,
  resolved,
}) {
  const credential =
    resolved ?? resolveGatewayCredential(configValue, config, processes, stateDir, envKey);
  if (credential.filePath)
    checkFilePermission(credential.filePath, reporter, "SecretRef file permissions");
  if (credential.status === "unknown") {
    reporter.unknown(
      label,
      `${mode} auth is configured via ${credential.source}, but its value could not be resolved safely.`,
    );
    return false;
  }
  if (credential.status !== "value") {
    if (processes.length === 0) {
      reporter.unknown(
        label,
        `${mode} auth is selected, but no ${mode} was found in config, state .env, or gateway.systemd.env; if it is supplied via another service environment or the Gateway process environment, start the Gateway and re-run.`,
      );
    } else {
      reporter.fail(
        label,
        `${mode} auth is selected, but no ${mode} was found in config or the Gateway process environment.`,
      );
    }
    return false;
  }
  const value = credential.value.trim();
  if (value.length === 0) {
    reporter.fail(label, `${mode} credential is empty (${credential.source}).`);
    return false;
  }
  if (weakValues.has(value)) {
    reporter.fail(
      label,
      `${mode} credential matches a published example placeholder; value was not printed.`,
    );
    return false;
  }
  if (mode === "token" && value.length < 24) {
    reporter.warn(
      label,
      `present via ${credential.source}, length ${value.length}; shorter than 24 characters.`,
    );
    return true;
  }
  reporter.pass(
    label,
    `present via ${credential.source}, length ${value.length}; value was not printed.`,
  );
  return true;
}

function checkAuth(config, processes, stateDir, bind, reporter) {
  const auth = isObject(config.gateway?.auth) ? config.gateway.auth : Object.create(null);
  let mode = typeof auth.mode === "string" ? auth.mode : undefined;
  let tokenCredential;
  let passwordCredential;
  if (!mode) {
    tokenCredential = resolveGatewayCredential(
      auth.token,
      config,
      processes,
      stateDir,
      "OPENCLAW_GATEWAY_TOKEN",
    );
    passwordCredential = resolveGatewayCredential(
      auth.password,
      config,
      processes,
      stateDir,
      "OPENCLAW_GATEWAY_PASSWORD",
    );
    const passwordAvailable =
      passwordCredential.status === "value" && passwordCredential.value.trim().length > 0;
    mode = passwordAvailable ? "password" : "token";
  }
  if (mode === "token") {
    checkOneSecret({
      label: "Gateway authentication",
      mode,
      configValue: auth.token,
      envKey: "OPENCLAW_GATEWAY_TOKEN",
      weakValues: KNOWN_WEAK_TOKENS,
      config,
      processes,
      stateDir,
      reporter,
      resolved: tokenCredential,
    });
  } else if (mode === "password") {
    checkOneSecret({
      label: "Gateway authentication",
      mode,
      configValue: auth.password,
      envKey: "OPENCLAW_GATEWAY_PASSWORD",
      weakValues: KNOWN_WEAK_PASSWORDS,
      config,
      processes,
      stateDir,
      reporter,
      resolved: passwordCredential,
    });
  } else if (mode === "trusted-proxy") {
    const userHeader = auth.trustedProxy?.userHeader;
    if (typeof userHeader !== "string" || userHeader.trim().length === 0) {
      reporter.fail(
        "Gateway authentication",
        "trusted-proxy mode has no non-empty gateway.auth.trustedProxy.userHeader.",
      );
    } else {
      const sharedToken = resolveGatewayCredential(
        auth.token,
        config,
        processes,
        stateDir,
        "OPENCLAW_GATEWAY_TOKEN",
      );
      const tokenInputConfigured =
        typeof auth.token === "string"
          ? auth.token.trim().length > 0
          : auth.token !== undefined && auth.token !== null;
      if (sharedToken.status === "value" && sharedToken.value.trim().length > 0) {
        reporter.fail(
          "Gateway authentication",
          "trusted-proxy mode also has a shared token configured; remove the conflicting token.",
        );
      } else if (
        (tokenInputConfigured && sharedToken.status === "unknown") ||
        processes.some((processInfo) => processInfo.env === null)
      ) {
        reporter.unknown(
          "Gateway authentication",
          "trusted-proxy userHeader is present, but a conflicting runtime token could not be ruled out.",
        );
      } else {
        reporter.pass(
          "Gateway authentication",
          "trusted-proxy mode has a non-empty userHeader; authentication is delegated to the proxy.",
        );
      }
    }
  } else {
    reporter.fail(
      "Gateway authentication",
      `auth mode is ${sanitize(mode)}; the Gateway has no shared-secret protection.`,
    );
  }
  if (
    bind.kind !== "loopback" &&
    ["token", "password"].includes(mode) &&
    !isObject(auth.rateLimit)
  ) {
    reporter.warn(
      "Authentication rate limit",
      "non-loopback shared-secret auth has no gateway.auth.rateLimit configuration.",
    );
  }
}

function checkControlUi(config, reporter) {
  const controlUi = config.gateway?.controlUi;
  if (!isObject(controlUi)) {
    reporter.pass("Control UI hardening", "no dangerous Control UI overrides are configured.");
    return;
  }
  const dangerous = [];
  if (controlUi.dangerouslyDisableDeviceAuth === true)
    dangerous.push("dangerouslyDisableDeviceAuth");
  if (controlUi.dangerouslyAllowHostHeaderOriginFallback === true) {
    dangerous.push("dangerouslyAllowHostHeaderOriginFallback");
  }
  if (controlUi.allowInsecureAuth === true) dangerous.push("allowInsecureAuth");
  if (dangerous.length === 0) {
    reporter.pass("Control UI hardening", "no dangerous Control UI overrides are enabled.");
  } else {
    reporter.fail("Control UI hardening", `enabled risky flags: ${dangerous.sort().join(", ")}.`);
  }
}

function findPackageRoot(explicitRoot, home) {
  const candidates = [];
  if (explicitRoot) {
    candidates.push(path.resolve(explicitRoot));
  } else {
    for (const directory of String(process.env.PATH ?? "").split(path.delimiter)) {
      if (!directory) continue;
      for (const binaryName of process.platform === "win32"
        ? ["openclaw.cmd", "openclaw.exe"]
        : ["openclaw"]) {
        const binPath = path.join(directory, binaryName);
        try {
          const resolved = fs.realpathSync(binPath);
          candidates.push(path.dirname(resolved));
        } catch {
          // Try the next PATH entry.
        }
      }
    }
    candidates.push(
      path.join(home, ".local", "lib", "node_modules", "openclaw"),
      "/usr/local/lib/node_modules/openclaw",
      "/usr/lib/node_modules/openclaw",
    );
  }
  for (const start of candidates) {
    let current = start;
    for (let depth = 0; depth < 6; depth += 1) {
      const manifestPath = path.join(current, "package.json");
      try {
        const manifest = JSON.parse(readLimited(manifestPath, 1024 * 1024));
        if (["openclaw", "clawdbot", "moltbot"].includes(manifest.name)) {
          return { root: current, version: manifest.version, manifestPath };
        }
      } catch {
        // Continue walking up.
      }
      const parent = path.dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }
  return null;
}

function compareReleaseVersion(version, fixed) {
  const pattern = /^(\d{4})\.(\d{1,2})\.(\d{1,2})(?:-([0-9A-Za-z.-]+))?$/u;
  const left = String(version ?? "").match(pattern);
  const right = fixed.match(pattern);
  if (!left || !right) return null;
  for (let index = 1; index <= 3; index += 1) {
    const difference = Number(left[index]) - Number(right[index]);
    if (difference !== 0) return Math.sign(difference);
  }
  if (!left[4]) return 0;
  if (/^\d+$/u.test(left[4])) return 1;
  if (/^(?:alpha|beta|rc)(?:\.|$)/iu.test(left[4])) return -1;
  return null;
}

function checkVersion(packageInfo, config, reporter) {
  const configVersion = config.meta?.lastTouchedVersion;
  const version =
    packageInfo?.version ?? (typeof configVersion === "string" ? configVersion : undefined);
  const source = packageInfo ? "installed package" : "config metadata";
  if (!version) {
    reporter.unknown("CVE-2026-25253", "could not determine an installed OpenClaw version.");
    return undefined;
  }
  const comparison = compareReleaseVersion(version, FIXED_VERSION);
  if (comparison === null) {
    reporter.unknown(
      "CVE-2026-25253",
      `${source} version ${sanitize(version)} cannot be compared safely.`,
    );
  } else if (comparison < 0) {
    reporter.fail(
      "CVE-2026-25253",
      `${source} version ${sanitize(version)} is older than fixed version ${FIXED_VERSION}.`,
    );
  } else {
    reporter.pass(
      "CVE-2026-25253",
      `${source} version ${sanitize(version)} is at or newer than ${FIXED_VERSION}.`,
    );
  }
  return version;
}

function gitInstallSpec(packageRoot) {
  if (!packageRoot) return undefined;
  const dotGit = path.join(packageRoot, ".git");
  try {
    const head = fs.readFileSync(path.join(dotGit, "HEAD"), "utf8").trim();
    if (head.startsWith("ref: refs/tags/"))
      return head.slice("ref: refs/tags/".length).replace(/^v/u, "");
    if (head.startsWith("ref: refs/heads/")) return head.slice("ref: refs/heads/".length);
    if (/^[0-9a-f]{40}$/iu.test(head)) return head;
  } catch {
    return undefined;
  }
  return undefined;
}

function checkInstallPin(options, packageInfo, installedVersion, reporter) {
  const spec =
    options.installSpec ?? process.env.OPENCLAW_INSTALL_SPEC ?? gitInstallSpec(packageInfo?.root);
  if (!spec) {
    reporter.unknown(
      "Installation pin",
      "package files do not retain whether npm/pnpm resolved @latest; pass --install-spec with the original install target.",
    );
    return;
  }
  const normalized = String(spec)
    .trim()
    .replace(/^openclaw@/u, "")
    .replace(/^v(?=\d)/u, "");
  if (
    ["latest", "next", "beta", "dev", "main", "master", "stable"].includes(normalized.toLowerCase())
  ) {
    reporter.warn(
      "Installation pin",
      `install target ${sanitize(normalized)} is moving rather than an exact release.`,
    );
    return;
  }
  const exactVersion = compareReleaseVersion(normalized, normalized) !== null;
  const commit = /^[0-9a-f]{40}$/iu.test(normalized);
  if (!exactVersion && !commit) {
    reporter.unknown(
      "Installation pin",
      `install target ${sanitize(normalized)} is not a recognized exact version or commit.`,
    );
    return;
  }
  if (exactVersion && installedVersion && normalized !== installedVersion) {
    reporter.warn(
      "Installation pin",
      `exact target ${sanitize(normalized)} does not match installed version ${sanitize(installedVersion)}.`,
    );
    return;
  }
  reporter.pass(
    "Installation pin",
    `exact target ${sanitize(normalized)} is recorded for this check.`,
  );
}

function walkForNamedFile(root, fileName, maxDepth, limit = MAX_INVENTORY_ITEMS) {
  const found = [];
  const stack = [{ directory: root, depth: 0 }];
  while (stack.length > 0 && found.length < limit) {
    const { directory, depth } = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(directory, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (found.length >= limit) break;
      if ([".git", ".cache"].includes(entry.name)) continue;
      const entryPath = path.join(directory, entry.name);
      if (entry.isFile() && entry.name === fileName) found.push(entryPath);
      else if ((entry.isDirectory() || entry.isSymbolicLink()) && depth < maxDepth) {
        stack.push({ directory: entryPath, depth: depth + 1 });
      }
    }
  }
  return found;
}

function parseManifest(filePath) {
  try {
    return parseJson5(readLimited(filePath, 1024 * 1024));
  } catch {
    return null;
  }
}

function pluginRoots(packageInfo, stateDir, configPath, config, home) {
  const roots = [];
  const add = (root, bundled, origin, depth) => {
    if (root && fs.existsSync(root)) roots.push({ root, bundled, origin, depth });
  };
  if (packageInfo) {
    add(path.join(packageInfo.root, "extensions"), true, "bundled", 3);
    add(path.join(packageInfo.root, "dist", "extensions"), true, "bundled", 3);
    add(path.join(packageInfo.root, "dist-runtime", "extensions"), true, "bundled", 3);
  }
  const configDir = path.dirname(configPath);
  add(path.join(stateDir, "extensions"), false, "managed/local", 5);
  add(path.join(stateDir, "plugins"), false, "managed/local", 5);
  add(path.join(stateDir, "npm", "projects"), false, "managed npm", 8);
  add(path.join(configDir, "extensions"), false, "config-dir managed/local", 5);
  add(path.join(configDir, "npm", "projects"), false, "config-dir managed npm", 8);
  const loadPaths = config.plugins?.load?.paths;
  if (Array.isArray(loadPaths)) {
    for (const entry of loadPaths) add(expandLocalPath(entry, home), false, "configured path", 4);
  }
  return roots;
}

function collectPlugins(packageInfo, stateDir, configPath, config, home, reporter) {
  const records = new Map();
  for (const rootInfo of pluginRoots(packageInfo, stateDir, configPath, config, home)) {
    for (const manifestPath of walkForNamedFile(
      rootInfo.root,
      "openclaw.plugin.json",
      rootInfo.depth,
    )) {
      const manifest = parseManifest(manifestPath);
      const fallback = path.basename(path.dirname(manifestPath));
      const id = sanitize(typeof manifest?.id === "string" ? manifest.id : fallback);
      const key = `${rootInfo.bundled ? "bundled" : "third"}:${id}`;
      if (!records.has(key)) records.set(key, { id, ...rootInfo, manifestPath, manifest });
    }
  }
  const bundledIds = new Set(
    [...records.values()].filter((entry) => entry.bundled).map((entry) => entry.id),
  );
  const configuredIds = new Set([
    ...Object.keys(isObject(config.plugins?.entries) ? config.plugins.entries : {}),
    ...Object.keys(isObject(config.plugins?.installs) ? config.plugins.installs : {}),
  ]);
  for (const id of configuredIds) {
    const safeId = sanitize(id);
    if (bundledIds.has(safeId)) continue;
    const alreadyFound = [...records.values()].some(
      (entry) => !entry.bundled && entry.id === safeId,
    );
    if (!alreadyFound) {
      records.set(`third:${safeId}`, {
        id: safeId,
        bundled: false,
        origin: "configured; files not located",
        manifest: null,
      });
    }
  }
  const bundled = [
    ...new Set([...records.values()].filter((entry) => entry.bundled).map((entry) => entry.id)),
  ].sort();
  const thirdParty = [
    ...new Set([...records.values()].filter((entry) => !entry.bundled).map((entry) => entry.id)),
  ].sort();
  reporter.info(
    "Bundled plugins",
    bundled.length > 0 ? `${bundled.length}: ${bundled.join(", ")}.` : "none found.",
  );
  if (thirdParty.length > 0) {
    reporter.warn(
      "Third-party plugins",
      `${thirdParty.length}: ${thirdParty.join(", ")}. Review them yourself; no malware verdict was attempted.`,
    );
  } else {
    reporter.pass("Third-party plugins", "none found in configured or managed install locations.");
  }
  return [...records.values()];
}

function skillName(skillFile) {
  let raw;
  try {
    const descriptor = fs.openSync(skillFile, "r");
    const buffer = Buffer.alloc(8192);
    const bytes = fs.readSync(descriptor, buffer, 0, buffer.length, 0);
    fs.closeSync(descriptor);
    raw = buffer.subarray(0, bytes).toString("utf8");
  } catch {
    return sanitize(path.basename(path.dirname(skillFile)));
  }
  const frontmatter = raw.startsWith("---") ? raw.slice(3, raw.indexOf("---", 3)) : "";
  const match = frontmatter.match(/^name:\s*["']?([a-z0-9][a-z0-9_-]{0,63})["']?\s*$/imu);
  return sanitize(match?.[1] ?? path.basename(path.dirname(skillFile)));
}

function collectSkills(packageInfo, stateDir, config, home, plugins, reporter) {
  const roots = [];
  const add = (root, bundled, origin, depth = 6) => {
    if (root && fs.existsSync(root)) roots.push({ root, bundled, origin, depth });
  };
  if (packageInfo) add(path.join(packageInfo.root, "skills"), true, "bundled");
  add(path.join(stateDir, "skills"), false, "managed/local");
  add(path.join(home, ".agents", "skills"), false, "personal agent");
  const workspaces = new Set([path.join(stateDir, "workspace")]);
  const defaultWorkspace = expandLocalPath(config.agents?.defaults?.workspace, home);
  if (defaultWorkspace) workspaces.add(defaultWorkspace);
  if (Array.isArray(config.agents?.list)) {
    for (const agent of config.agents.list) {
      const workspace = expandLocalPath(agent?.workspace, home);
      if (workspace) workspaces.add(workspace);
    }
  }
  for (const workspace of workspaces) {
    add(path.join(workspace, "skills"), false, "workspace");
    add(path.join(workspace, ".agents", "skills"), false, "project agent");
  }
  if (Array.isArray(config.skills?.load?.extraDirs)) {
    for (const entry of config.skills.load.extraDirs)
      add(expandLocalPath(entry, home), false, "extra directory");
  }
  for (const plugin of plugins) {
    if (!plugin.manifestPath || !Array.isArray(plugin.manifest?.skills)) continue;
    for (const entry of plugin.manifest.skills) {
      if (typeof entry !== "string") continue;
      add(
        path.resolve(path.dirname(plugin.manifestPath), entry),
        plugin.bundled,
        plugin.bundled ? "bundled plugin" : "third-party plugin",
      );
    }
  }
  const records = [];
  for (const rootInfo of roots) {
    for (const skillFile of walkForNamedFile(rootInfo.root, "SKILL.md", rootInfo.depth)) {
      records.push({ name: skillName(skillFile), ...rootInfo });
    }
  }
  const bundled = [
    ...new Set(records.filter((entry) => entry.bundled).map((entry) => entry.name)),
  ].sort();
  const thirdParty = [
    ...new Set(records.filter((entry) => !entry.bundled).map((entry) => entry.name)),
  ].sort();
  reporter.info(
    "Bundled skills",
    bundled.length > 0 ? `${bundled.length}: ${bundled.join(", ")}.` : "none found.",
  );
  if (thirdParty.length > 0) {
    reporter.warn(
      "Third-party skills",
      `${thirdParty.length}: ${thirdParty.join(", ")}. Review them yourself; no malware verdict was attempted.`,
    );
  } else {
    reporter.pass("Third-party skills", "none found in configured user-managed locations.");
  }
}

function collectSecretFiles(configPath, loadedFiles, stateDir) {
  const files = new Set([configPath, ...loadedFiles]);
  for (const envFile of [".env", SYSTEMD_GATEWAY_ENV_FILENAME]) {
    const filePath = path.join(stateDir, envFile);
    if (fs.existsSync(filePath)) files.add(filePath);
  }
  for (const filePath of walkForNamedFile(
    path.join(stateDir, "agents"),
    "auth-profiles.json",
    4,
    200,
  )) {
    files.add(filePath);
  }
  const credentialsDir = path.join(stateDir, "credentials");
  if (fs.existsSync(credentialsDir)) {
    for (const filePath of walkForNamedFile(credentialsDir, "oauth.json", 3, 200))
      files.add(filePath);
  }
  return [...files];
}

function printHeader(configPath) {
  console.log("OpenClaw hardening check");
  console.log("Read-only and offline. Secret values are never printed.");
  console.log(`Config: ${displayPath(configPath)}`);
  console.log("");
}

function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(`Error: ${error.message}`);
    console.error(usage());
    return 2;
  }
  if (options.help) {
    console.log(usage());
    return 0;
  }
  const paths = resolvePaths(options);
  printHeader(paths.configPath);
  const reporter = new Reporter();
  let loaded;
  try {
    loaded = loadConfigWithIncludes(paths.configPath);
    reporter.pass(
      "Config",
      `loaded ${displayPath(paths.configPath)} without printing its contents.`,
    );
  } catch (error) {
    const safeMessage =
      error instanceof SafeError ? error.message : "Could not parse the config safely.";
    reporter.fail("Config", safeMessage);
    console.log("");
    console.log("Summary: config could not be read; exit code 2.");
    return 2;
  }
  const { config, loadedFiles } = loaded;
  const processDiscovery = findGatewayProcesses(paths.configPath, paths.stateDir);
  const bind = checkBind(config, reporter);
  checkAuth(config, processDiscovery.processes, paths.stateDir, bind, reporter);
  checkControlUi(config, reporter);
  const gatewayPort = resolveGatewayPort(config, processDiscovery.processes);
  reporter.info("Gateway port", `${gatewayPort} (config/Gateway-process precedence applied).`);
  checkRuntimeSockets(processDiscovery, gatewayPort, reporter);

  const packageInfo = findPackageRoot(options.packageRoot, paths.home);
  const installedVersion = checkVersion(packageInfo, config, reporter);
  checkInstallPin(options, packageInfo, installedVersion, reporter);

  for (const filePath of collectSecretFiles(paths.configPath, loadedFiles, paths.stateDir)) {
    checkFilePermission(filePath, reporter);
  }

  const plugins = collectPlugins(
    packageInfo,
    paths.stateDir,
    paths.configPath,
    config,
    paths.home,
    reporter,
  );
  collectSkills(packageInfo, paths.stateDir, config, paths.home, plugins, reporter);

  console.log("");
  return printSummary(reporter);
}

function isDirectRun() {
  if (!process.argv[1]) return false;
  try {
    return fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));
  }
}

if (isDirectRun()) process.exitCode = main();

export { configuredBind, detectContainerEnvironment, isGatewayArgv, resolveGatewayCredential };
