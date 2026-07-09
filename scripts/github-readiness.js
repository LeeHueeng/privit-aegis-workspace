import { spawnSync } from "node:child_process";

function parseArgs(argv) {
  const args = argv.slice(2);
  return {
    json: args.includes("--json") || (args.includes("--format") && args[args.indexOf("--format") + 1] === "json"),
    strict: args.includes("--strict")
  };
}

function run(command, args, timeout = 15000) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout
  });
  return {
    ok: result.status === 0,
    status: result.status ?? 1,
    stdout: (result.stdout || "").trim(),
    stderr: (result.stderr || "").trim()
  };
}

function parseJson(value, fallback) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function normalizeRemote(value) {
  const remote = value.trim();
  const https = remote.match(/^https:\/\/github\.com\/([^/]+)\/([^/.]+)(?:\.git)?$/i);
  if (https) return `${https[1]}/${https[2]}`;
  const ssh = remote.match(/^git@github\.com:([^/]+)\/([^/.]+)(?:\.git)?$/i);
  if (ssh) return `${ssh[1]}/${ssh[2]}`;
  return "";
}

function getRepository() {
  const remote = run("git", ["remote", "get-url", "origin"], 5000);
  const parsed = remote.ok ? normalizeRemote(remote.stdout) : "";
  if (parsed) return parsed;

  const ghRepo = run("gh", ["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"], 10000);
  return ghRepo.ok ? ghRepo.stdout : "";
}

function getCurrentBranch() {
  const branch = run("git", ["branch", "--show-current"], 5000);
  return branch.ok && branch.stdout ? branch.stdout : "main";
}

function checkGhAuth() {
  const auth = run("gh", ["auth", "status"], 10000);
  return {
    ok: auth.ok,
    detail: auth.ok ? "gh authenticated" : auth.stderr || auth.stdout || "gh is not authenticated"
  };
}

function checkSecret(repo) {
  if (!repo) {
    return { ok: false, present: false, detail: "GitHub repository could not be resolved." };
  }

  const listed = run("gh", ["secret", "list", "--repo", repo], 15000);
  if (!listed.ok) {
    return {
      ok: false,
      present: false,
      detail: listed.stderr || listed.stdout || "Could not list repository secrets."
    };
  }

  const secrets = listed.stdout.split(/\r?\n/).map((line) => line.split(/\s+/)[0]).filter(Boolean);
  const tokenPresent = secrets.includes("AEGIS_CLI_TOKEN");
  const sshKeyPresent = secrets.includes("AEGIS_CLI_SSH_KEY");
  const present = tokenPresent || sshKeyPresent;
  return {
    ok: present,
    present,
    tokenPresent,
    sshKeyPresent,
    detail: present
      ? `Aegis CLI credential exists (${sshKeyPresent ? "AEGIS_CLI_SSH_KEY" : "AEGIS_CLI_TOKEN"}). Secret values are never readable through this check.`
      : "Aegis CLI credential is missing. Configure AEGIS_CLI_SSH_KEY or AEGIS_CLI_TOKEN."
  };
}

function checkLatestRun(repo, branch) {
  if (!repo) {
    return { ok: false, detail: "GitHub repository could not be resolved." };
  }

  const runs = run("gh", [
    "run",
    "list",
    "--repo",
    repo,
    "--branch",
    branch,
    "--limit",
    "1",
    "--json",
    "databaseId,status,conclusion,displayTitle,workflowName,createdAt,url"
  ]);

  if (!runs.ok) {
    return {
      ok: false,
      detail: runs.stderr || runs.stdout || "Could not read GitHub Actions runs."
    };
  }

  const [latest] = parseJson(runs.stdout, []);
  if (!latest) {
    return { ok: false, detail: "No GitHub Actions runs found for this branch." };
  }

  const ok = latest.status === "completed" && latest.conclusion === "success";
  return {
    ok,
    latest,
    detail: `${latest.workflowName || "workflow"}: ${latest.status}/${latest.conclusion || "none"} (${latest.displayTitle || "run"})`
  };
}

function checkBranchProtection(repo, branch) {
  if (!repo) {
    return { ok: false, enforced: false, detail: "GitHub repository could not be resolved." };
  }

  const protection = run("gh", ["api", `repos/${repo}/branches/${branch}/protection/required_status_checks`]);
  if (!protection.ok) {
    const detail = protection.stderr || protection.stdout || "Required status checks are not verified.";
    return {
      ok: false,
      enforced: false,
      detail: detail.includes("403")
        ? "Required status checks could not be verified. Private repository protection may require admin access or a GitHub plan that supports it."
        : detail
    };
  }

  const data = parseJson(protection.stdout, {});
  const contexts = [
    ...(Array.isArray(data.contexts) ? data.contexts : []),
    ...(Array.isArray(data.checks) ? data.checks.map((check) => check.context).filter(Boolean) : [])
  ];
  const hasAigate = contexts.some((context) => /aigate/i.test(context));
  return {
    ok: hasAigate,
    enforced: hasAigate,
    contexts,
    detail: hasAigate
      ? "AIGate is configured as a required status check."
      : "Branch protection exists, but AIGate is not verified as a required status check."
  };
}

function getAigateScore() {
  const score = run("aigate", ["evaluate-project", "--format", "json", "--deep"], 30000);
  if (!score.ok) {
    return {
      ok: false,
      score: null,
      detail: score.stderr || score.stdout || "Could not evaluate AIGate score."
    };
  }

  const data = parseJson(score.stdout, {});
  const cap = data.scoreAdjustments?.find((item) => item.type === "cap");
  return {
    ok: true,
    score: data.score,
    grade: data.grade,
    cap: cap?.cap,
    reason: cap?.reason || "",
    detail: `AIGate score ${data.score}/100${data.grade ? ` (${data.grade})` : ""}`
  };
}

function buildReport() {
  const repository = getRepository();
  const branch = getCurrentBranch();
  const ghAuth = checkGhAuth();
  const aegisCliToken = ghAuth.ok
    ? checkSecret(repository)
    : { ok: false, present: false, detail: "gh auth is required before checking secrets." };
  const latestRun = ghAuth.ok
    ? checkLatestRun(repository, branch)
    : { ok: false, detail: "gh auth is required before checking workflow runs." };
  const branchProtection = ghAuth.ok
    ? checkBranchProtection(repository, branch)
    : { ok: false, enforced: false, detail: "gh auth is required before checking branch protection." };
  const aigate = getAigateScore();

  const blockers = [];
  if (!ghAuth.ok) blockers.push("gh authentication is not ready");
  if (!aegisCliToken.ok) blockers.push("Aegis CLI credential secret is missing or not visible");
  if (!branchProtection.ok) blockers.push("AIGate required status check is not verified");
  if (latestRun.latest && !latestRun.ok) blockers.push("latest GitHub Actions run is not successful");
  const nextSteps = [];
  if (!aegisCliToken.ok) {
    nextSteps.push(
      "Create either a read-only deploy key for LeeHueeng/privit-project or a fine-grained GitHub token with read access.",
      "Store it as AEGIS_CLI_SSH_KEY or AEGIS_CLI_TOKEN in this repository."
    );
  }
  if (latestRun.latest && !latestRun.ok) {
    nextSteps.push("Rerun the latest GitHub Actions workflow after the credential fix is pushed.");
  }
  if (!branchProtection.ok) {
    nextSteps.push("Enable branch protection or a ruleset that requires the AIGate check on main when the GitHub plan allows it.");
  }

  return {
    command: "github-readiness",
    status: blockers.length ? "BLOCKED" : "READY",
    repository,
    branch,
    generatedAt: new Date().toISOString(),
    checks: {
      ghAuth,
      aegisCliToken,
      latestRun,
      branchProtection,
      aigate
    },
    blockers,
    nextSteps
  };
}

function printHuman(report) {
  console.log(`GitHub readiness: ${report.status}`);
  console.log(`Repository: ${report.repository || "unknown"}`);
  console.log(`Branch: ${report.branch}`);
  console.log("");
  for (const [name, check] of Object.entries(report.checks)) {
    console.log(`- ${check.ok ? "PASS" : "TODO"} ${name}: ${check.detail}`);
  }
  if (report.checks.aigate?.reason) {
    console.log(`- INFO aigate cap: ${report.checks.aigate.reason}`);
  }
  if (report.nextSteps.length) {
    console.log("");
    console.log("Next steps:");
    for (const step of report.nextSteps) {
      console.log(`- ${step}`);
    }
  }
}

const options = parseArgs(process.argv);
const report = buildReport();

if (options.json) {
  console.log(JSON.stringify(report, null, 2));
} else {
  printHuman(report);
}

if (options.strict && report.status !== "READY") {
  process.exit(1);
}
