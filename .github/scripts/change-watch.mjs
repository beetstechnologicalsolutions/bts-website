// Flags any pushed change that goes beyond the news and vulnerability data.
//
// Usage: node change-watch.mjs <base-sha> <head-sha> <alert-out>
// Writes <alert-out> (Markdown) only when something outside the data block of
// public/index.html changed. Read-only: it never changes the repository.

import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";

const [base, head, alertFile] = process.argv.slice(2);
if (!base || !head || !alertFile) {
  console.error("Usage: node change-watch.mjs <base-sha> <head-sha> <alert-out>");
  process.exit(2);
}

const git = (...args) => execFileSync("git", args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
const SITE = "public/index.html";

function showFile(sha, path) {
  try { return git("show", `${sha}:${path}`); } catch { return null; }
}

function withoutData(html) {
  if (html === null) return null;
  const s = html.indexOf("/* DATA:START */");
  const e = html.indexOf("/* DATA:END */");
  if (s < 0 || e < s) return html; // markers missing: compare the whole page
  return html.slice(0, s) + html.slice(e);
}

const changed = git("diff", "--name-status", "--no-renames", base, head)
  .trim().split("\n").filter(Boolean)
  .map((l) => { const [status, ...p] = l.split("\t"); return { status, path: p.join("\t") }; });

const problems = [];
for (const { status, path } of changed) {
  if (path === SITE && status === "M") {
    const before = withoutData(showFile(base, SITE));
    const after = withoutData(showFile(head, SITE));
    if (before !== after) problems.push(`- \`${SITE}\`: changed **outside** the news and vulnerability data block`);
    else if (!(showFile(head, SITE) || "").includes("/* DATA:END */")) problems.push(`- \`${SITE}\`: the data block markers are missing`);
  } else {
    const what = { A: "added", D: "deleted", M: "changed" }[status[0]] || `status ${status}`;
    problems.push(`- \`${path}\`: ${what}`);
  }
}

console.log(`${changed.length} file(s) changed, ${problems.length} outside the data block.`);
if (problems.length === 0) process.exit(0);

const commits = git("log", "--format=- %h %an: %s", `${base}..${head}`).trim() || "(no commit list available)";
writeFileSync(alertFile, [
  "A push to the BTS website repository changed something other than the news and vulnerability data.",
  "",
  "**What changed**",
  ...problems,
  "",
  "**Commits**",
  commits.replace(/[<>]/g, ""),
  "",
  "If you or someone you trust made this change on purpose, close this issue.",
  "If not, treat it as a possible compromise: change your GitHub password, check Settings, Sessions and Settings, SSH and GPG keys for anything you don't recognise, then revert the commit and check Vercel's deployments.",
].join("\n"));
