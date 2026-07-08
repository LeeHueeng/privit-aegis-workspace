import { readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";

const scopePath = "aegis.scope.json";

function hostFromUrl(value) {
  try {
    return new URL(value).hostname;
  } catch {
    return "localhost";
  }
}

async function ask(question, fallback, rl) {
  if (!process.stdin.isTTY) {
    return fallback;
  }
  const answer = await rl.question(`${question} (${fallback}): `);
  return answer.trim() || fallback;
}

if (!existsSync(scopePath)) {
  console.error("aegis.scope.json not found. Run `npm run security:init` first.");
  process.exit(1);
}

const scope = JSON.parse(await readFile(scopePath, "utf8"));
const rl = createInterface({ input, output });

try {
  const project = await ask("Project name", scope.project || "privit", rl);
  const environment = await ask("Environment", scope.environment || "local", rl);
  const frontendUrl = await ask("Frontend base URL", scope.targets?.frontend?.base_url || "http://localhost:3000", rl);
  const owner = await ask("Authorization owner email", scope.authorization?.owner || "security@example.com", rl);

  scope.project = project;
  scope.environment = environment;
  scope.targets ||= {};
  scope.targets.frontend ||= { enabled: true };
  scope.targets.frontend.enabled = true;
  scope.targets.frontend.base_url = frontendUrl;
  scope.targets.frontend.allowed_hosts = [...new Set([hostFromUrl(frontendUrl), ...(scope.targets.frontend.allowed_hosts || [])])];
  scope.targets.frontend.allowed_paths ||= ["/*"];
  scope.targets.frontend.denied_paths ||= ["/payments/live/*", "/admin/delete/*"];
  scope.authorization ||= {};
  scope.authorization.owner = owner;

  await writeFile(scopePath, `${JSON.stringify(scope, null, 2)}\n`, "utf8");
  console.log(`Updated ${scopePath}`);
  console.log(`Next: npm run start:aegis`);
} finally {
  rl.close();
}
