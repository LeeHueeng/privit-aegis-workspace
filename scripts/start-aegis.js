import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";

const steps = [
  existsSync("aegis.scope.json") ? null : ["aegis", ["init"]],
  ["aegis", ["catalog", "generate"]],
  ["aegis", ["docs", "generate", "--lang", "all"]],
  ["aegis", ["scope", "verify", "--mode", "passive"]],
  ["aegis", ["plan", "--mode", "passive", "--target", "frontend", "--limit", "50"]],
  ["aegis", ["run", "--target", "frontend", "--mode", "passive", "--crawl", "true", "--max-depth", "2", "--max-pages", "50"]],
  ["node", ["./scripts/frontend-advisory.js"]],
  ["npm", ["run", "security:report"]],
  ["npm", ["run", "security:penetration"]]
].filter(Boolean);

for (const [command, args] of steps) {
  console.log(`\n$ ${command} ${args.join(" ")}`);
  const result = spawnSync(command, args, { stdio: "inherit" });
  if (result.status !== 0) {
    process.exit(result.status || 1);
  }
}

console.log("\nAegis start flow complete.");
