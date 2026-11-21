// Checks CISA's Known Exploited Vulnerabilities (KEV) catalogue for new entries
// and writes an alert for any that the website doesn't list yet.
//
// Usage: node kev-alert.mjs <seen-file> <site-html> <alert-out>
//   seen-file : JSON list of CVE IDs already handled (created on first run)
//   site-html : public/index.html, used to skip CVEs the site already covers
//   alert-out : written only when there is something new (Markdown issue body)
//
// It never changes the website. It only reads CISA's public data.

import { readFileSync, writeFileSync, existsSync } from "node:fs";

const [seenFile, siteFile, alertFile] = process.argv.slice(2);
if (!seenFile || !siteFile || !alertFile) {
  console.error("Usage: node kev-alert.mjs <seen-file> <site-html> <alert-out>");
  process.exit(2);
}

const SOURCES = [
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
  "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
];

async function loadKev() {
  for (const url of SOURCES) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(60_000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (!Array.isArray(data.vulnerabilities)) throw new Error("unexpected format");
      console.log(`Loaded ${data.vulnerabilities.length} KEV entries from ${url}`);
      return data.vulnerabilities;
    } catch (err) {
      console.log(`Could not load ${url}: ${err.message}`);
    }
  }
  throw new Error("Could not load the KEV catalogue from any source");
}

const CVE_RE = /^CVE-\d{4}-\d{4,}$/;
const kev = (await loadKev()).filter((v) => CVE_RE.test(v.cveID || ""));

const firstRun = !existsSync(seenFile);
const seen = new Set(firstRun ? [] : JSON.parse(readFileSync(seenFile, "utf8")));

// The data block of the site, so CVEs the site already lists don't raise an alert.
const html = readFileSync(siteFile, "utf8");
const start = html.indexOf("/* DATA:START */");
const end = html.indexOf("/* DATA:END */");
const dataBlock = start >= 0 && end > start ? html.slice(start, end) : html;

const fresh = kev.filter((v) => !seen.has(v.cveID));
for (const v of kev) seen.add(v.cveID);
writeFileSync(seenFile, JSON.stringify([...seen].sort()));

if (firstRun) {
  console.log(`First run: recorded ${seen.size} existing entries. No alert sent.`);
  process.exit(0);
}

const missing = fresh.filter((v) => !dataBlock.includes(v.cveID));
console.log(`${fresh.length} new KEV entries, ${missing.length} not yet on the website.`);
if (missing.length === 0) process.exit(0);

// Plain text from CISA's data, with characters that could form Markdown or HTML neutralised.
const clean = (s) =>
  String(s ?? "")
    .replace(/[<>]/g, "")
    .replace(/[\r\n]+/g, " ")
    .replace(/([\\`*_\[\]|#])/g, "\\$1")
    .trim();

const lines = [
  `CISA has added ${missing.length === 1 ? "a vulnerability" : `${missing.length} vulnerabilities`} to its Known Exploited Vulnerabilities list that the BTS website doesn't show yet.`,
  "",
];
for (const v of missing) {
  lines.push(`### ${v.cveID}: ${clean(v.vendorProject)} ${clean(v.product)}`);
  lines.push(`- **Name:** ${clean(v.vulnerabilityName)}`);
  lines.push(`- **Added to KEV:** ${clean(v.dateAdded)}`);
  if (v.knownRansomwareCampaignUse === "Known") lines.push("- **Used in ransomware campaigns:** yes");
  lines.push(`- **What it is:** ${clean(v.shortDescription)}`);
  lines.push(`- **Action:** ${clean(v.requiredAction)}`);
  lines.push(`- **Details:** https://nvd.nist.gov/vuln/detail/${v.cveID}`);
  lines.push("");
}
lines.push("The hourly website update will add these automatically. To add them sooner, start the \"BTS website threat feed update\" scheduled task now from Claude.");
lines.push("");
lines.push("Close this issue once the site shows them.");

writeFileSync(alertFile, lines.join("\n"));
writeFileSync(alertFile + ".title", `New exploited vulnerabilities: ${missing.map((v) => v.cveID).join(", ")}`.slice(0, 250));
