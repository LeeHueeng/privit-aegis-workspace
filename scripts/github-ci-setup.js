import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    stdio: options.stdio || (options.input === undefined ? ["ignore", "pipe", "pipe"] : ["pipe", "pipe", "pipe"]),
    input: options.input,
    timeout: options.timeout || 15000
  });
  return {
    ok: result.status === 0,
    status: result.status ?? 1,
    stdout: (result.stdout || "").trim(),
    stderr: (result.stderr || "").trim()
  };
}

function normalizeRemote(value) {
  const remote = value.trim();
  const https = remote.match(/^https:\/\/github\.com\/([^/]+)\/([^/.]+)(?:\.git)?$/i);
  if (https) return `${https[1]}/${https[2]}`;
  const ssh = remote.match(/^git@github\.com:([^/]+)\/([^/.]+)(?:\.git)?$/i);
  if (ssh) return `${ssh[1]}/${ssh[2]}`;
  return "";
}

function repository() {
  const remote = run("git", ["remote", "get-url", "origin"], { timeout: 5000 });
  const repo = remote.ok ? normalizeRemote(remote.stdout) : "";
  if (repo) return repo;
  const viewed = run("gh", ["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"]);
  return viewed.ok ? viewed.stdout : "";
}

function readToken() {
  if (process.env.AEGIS_CLI_TOKEN) {
    return process.env.AEGIS_CLI_TOKEN.trim();
  }

  if (!process.stdin.isTTY) {
    return readFileSync(0, "utf8").trim();
  }

  console.error("Provide the token through AEGIS_CLI_TOKEN or stdin:");
  console.error("  AEGIS_CLI_TOKEN=... npm run github:secret:set");
  console.error("  printf '%s' \"$TOKEN\" | npm run github:secret:set");
  process.exit(2);
}

const repo = repository();
if (!repo) {
  console.error("Could not resolve the GitHub repository.");
  process.exit(1);
}

const token = readToken();
if (!token) {
  console.error("AEGIS_CLI_TOKEN is empty.");
  process.exit(2);
}

const auth = run("gh", ["auth", "status"], { timeout: 10000 });
if (!auth.ok) {
  console.error(auth.stderr || auth.stdout || "gh is not authenticated.");
  process.exit(auth.status || 1);
}

const result = run("gh", ["secret", "set", "AEGIS_CLI_TOKEN", "--repo", repo, "--body-file", "-"], {
  input: token,
  timeout: 20000
});

if (!result.ok) {
  console.error(result.stderr || result.stdout || "Failed to set AEGIS_CLI_TOKEN.");
  process.exit(result.status || 1);
}

console.log(`AEGIS_CLI_TOKEN secret saved for ${repo}.`);
console.log("Run `npm run github:ready` to verify status.");
