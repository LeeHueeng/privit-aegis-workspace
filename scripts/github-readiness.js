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

function checkAegisCliSource() {
  const result = run("gh", ["repo", "view", "LeeHueeng/privit-project", "--json", "visibility,url,defaultBranchRef"], 15000);
  if (!result.ok) {
    return {
      ok: false,
      detail: result.stderr || result.stdout || "Could not verify the Aegis CLI source repository."
    };
  }

  const data = parseJson(result.stdout, {});
  const publicRepo = data.visibility === "PUBLIC";
  return {
    ok: publicRepo,
    visibility: data.visibility || "unknown",
    url: data.url || "https://github.com/LeeHueeng/privit-project",
    defaultBranch: data.defaultBranchRef?.name || "",
    detail: publicRepo
      ? "Aegis CLI source repository is public and can be installed without CI secrets."
      : `Aegis CLI source repository is ${data.visibility || "unknown"}; public CI install may require secrets.`
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
        ? "Required status checks could not be verified. Confirm admin access and branch protection availability."
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
  const aegisCliSource = ghAuth.ok
    ? checkAegisCliSource()
    : { ok: false, detail: "gh auth is required before checking the Aegis CLI source repository." };
  const latestRun = ghAuth.ok
    ? checkLatestRun(repository, branch)
    : { ok: false, detail: "gh auth is required before checking workflow runs." };
  const branchProtection = ghAuth.ok
    ? checkBranchProtection(repository, branch)
    : { ok: false, enforced: false, detail: "gh auth is required before checking branch protection." };
  const aigate = getAigateScore();

  const blockers = [];
  if (!ghAuth.ok) blockers.push("gh authentication is not ready");
  if (!aegisCliSource.ok) blockers.push("Aegis CLI source repository is not public");
  if (!branchProtection.ok) blockers.push("AIGate required status check is not verified");
  if (latestRun.latest && !latestRun.ok) blockers.push("latest GitHub Actions run is not successful");
  const nextSteps = [];
  if (!aegisCliSource.ok) {
    nextSteps.push(
      "Make LeeHueeng/privit-project public or restore a credentialed install path in CI."
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
      aegisCliSource,
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
