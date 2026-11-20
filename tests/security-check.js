// BTS website pre-publish security check.
// Usage: node security-check.js <page.html>
// Exits 0 when every check passes, 1 when any check fails.
"use strict";
const fs = require("fs");
const vm = require("vm");

const file = process.argv[2];
if (!file) { console.error("Usage: node security-check.js <page.html>"); process.exit(2); }
const html = fs.readFileSync(file, "utf8");
const fails = [];
const warn = [];
const fail = (m) => fails.push(m);

// 1. Page structure: no new script sources, frames, embeds or form targets.
const scriptSrcs = [...html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]+)/gi)].map(m => m[1]);
if (scriptSrcs.length) fail("External script tags found: " + scriptSrcs.join(", "));
const inlineScripts = (html.match(/<script\b(?![^>]*\bsrc)[^>]*>/gi) || []).length;
if (inlineScripts !== 1) fail("Expected exactly 1 inline <script>, found " + inlineScripts);
if (/<(iframe|object|embed|frame|base)\b/i.test(html)) fail("Disallowed tag (iframe/object/embed/frame/base) found");
if (/<form\b[^>]*\baction\s*=/i.test(html)) fail("A form has an action attribute (data could be sent off-site)");
if (/<meta\b[^>]*http-equiv\s*=\s*["']?refresh/i.test(html)) fail("Meta refresh redirect found");

// Inline event handlers in markup (outside the script block).
const markup = html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "").replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, "");
const handlers = markup.match(/\son[a-z]+\s*=/gi);
if (handlers) fail("Inline event handlers in markup: " + [...new Set(handlers)].join(" "));
if (/javascript:/i.test(markup)) fail("javascript: URL found in markup");

// Stylesheets/links only from allowed hosts.
const linkHrefs = [...markup.matchAll(/<link\b[^>]*\bhref\s*=\s*["']([^"']+)/gi)].map(m => m[1]);
for (const h of linkHrefs) {
  // Allowed: Google Fonts, and the site's own files (such as /favicon.svg).
  if (!/^https:\/\/fonts\.(googleapis|gstatic)\.com(\/|$)/.test(h) && !/^\/[a-z0-9._-]+$/i.test(h)) fail("Unexpected <link> host: " + h);
}

// 2. The data block: isolate, make sure it only declares data.
const m = html.match(/\/\* DATA:START \*\/([\s\S]*?)\/\* DATA:END \*\//);
if (!m) { fail("DATA:START / DATA:END markers missing"); report(); }
const block = m[1];
const outside = html.replace(m[0], "");
if (/\/\* DATA:(START|END) \*\//.test(outside)) fail("Duplicate DATA markers found");
// The browser's HTML parser runs before any page code, so these would break out
// of the <script> tag no matter how the page escapes things later.
if (/<\/?\s*script|<!--|<\/|<[a-z!?]/i.test(block)) fail("The data block contains raw '<' markup (could break out of the script tag)");

// Only three top-level declarations allowed, nothing executable.
const stripped = block.replace(/"(?:[^"\\]|\\.)*"/g, '""').replace(/'(?:[^'\\]|\\.)*'/g, "''");
const decls = (stripped.match(/\bvar\s+([A-Za-z_$][\w$]*)/g) || []).map(s => s.replace(/var\s+/, ""));
if (decls.sort().join(",") !== "NEWS,UPDATED,VULNS") fail("Data block declares unexpected variables: " + decls.join(", "));
if (/\b(function|=>|eval|new\s|import|require|fetch|XMLHttpRequest|document|window|location|setTimeout|setInterval|constructor|__proto__|prototype)\b/.test(stripped))
  fail("Executable code or dangerous identifiers found in the data block");
if (/[`]/.test(block)) fail("Template literals are not allowed in the data block");
if (/\(\s*[^)]*\)/.test(stripped.replace(/\/\*[\s\S]*?\*\//g, ""))) fail("Function call syntax found in the data block");

let data;
try {
  const sandbox = Object.create(null);
  vm.runInNewContext(block + "\n;__out={UPDATED,VULNS,NEWS};", sandbox, { timeout: 1000 });
  data = sandbox.__out;
} catch (e) { fail("Data block does not evaluate cleanly: " + e.message); report(); }

// 3. Schema and content checks on every item.
const SEV = ["critical", "high", "medium"];
const REG = ["UK", "Nigeria", "Europe", "Americas", "Asia-Pacific", "Africa", "Middle East", "Global"];
const DATE = /^\d{1,2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4}$/;
const BAD = /<|>|javascript:|data:|vbscript:|on[a-z]+\s*=|&#|\\u00|%3c/i;
const BLOCKED_HOSTS = /(substack\.com|medium\.com|blogspot\.|wordpress\.com|bit\.ly|tinyurl\.com|t\.co\/|goo\.gl|ow\.ly|pastebin|telegram|t\.me\/|discord|reddit\.com|facebook\.com|x\.com\/|twitter\.com)/i;

if (typeof data.UPDATED !== "string" || !/^\d{1,2} [A-Z][a-z]{2} \d{4}(, \d{2}:\d{2})?$/.test(data.UPDATED)) fail("UPDATED has the wrong format: " + data.UPDATED);
if (!Array.isArray(data.VULNS) || data.VULNS.length < 1 || data.VULNS.length > 50) fail("VULNS must be an array of 1 to 50 items");
if (!Array.isArray(data.NEWS) || data.NEWS.length < 1 || data.NEWS.length > 12) fail("NEWS must be an array of 1 to 12 items");

function checkUrl(u, where) {
  let p;
  try { p = new URL(u); } catch { fail(where + ": url is not valid: " + u); return; }
  if (p.protocol !== "https:") fail(where + ": url must use https: " + u);
  if (p.username || p.password) fail(where + ": url contains credentials");
  if (/^\d+\.\d+\.\d+\.\d+$/.test(p.hostname) || p.hostname.includes(":")) fail(where + ": url uses a raw IP address");
  if (p.port) fail(where + ": url uses a non-standard port");
  if (/xn--/i.test(p.hostname)) fail(where + ": url uses a punycode (look-alike) domain: " + p.hostname);
  if (BLOCKED_HOSTS.test(u)) fail(where + ": url is on a blocked host (blog, shortener or social): " + u);
  if (/["'\s<>]/.test(u)) fail(where + ": url contains unsafe characters");
}
function checkStrings(obj, keys, where) {
  for (const k of Object.keys(obj)) if (!keys.includes(k)) fail(where + ": unexpected field '" + k + "'");
  for (const k of keys) {
    const v = obj[k];
    if (k === "score" && v === null) continue;
    if (typeof v !== "string" || !v.trim()) { fail(where + ": field '" + k + "' must be a non-empty string"); continue; }
    if (k !== "url" && BAD.test(v)) fail(where + ": field '" + k + "' contains markup or script-like content");
    if (v.length > 600) fail(where + ": field '" + k + "' is too long (" + v.length + " chars)");
  }
}

const seenIds = new Set();
data.VULNS.forEach((v, i) => {
  const w = "VULNS[" + i + "] " + (v && v.id);
  checkStrings(v, ["id", "sev", "score", "product", "title", "what", "fix", "added", "src", "url"], w);
  if (!/^CVE-\d{4}-\d{4,}$/.test(v.id)) fail(w + ": id is not a CVE ID");
  if (seenIds.has(v.id)) fail(w + ": duplicate CVE"); seenIds.add(v.id);
  if (!SEV.includes(v.sev)) fail(w + ": sev must be one of " + SEV.join("/"));
  if (v.score !== null) {
    const n = Number(v.score);
    if (!/^\d{1,2}\.\d$/.test(v.score) || n < 0 || n > 10) fail(w + ": score must look like 9.8");
    else {
      const expect = n >= 9 ? "critical" : n >= 7 ? "high" : "medium";
      if (expect !== v.sev) fail(w + ": sev '" + v.sev + "' does not match CVSS " + v.score);
    }
  }
  checkUrl(v.url, w);
});
const seenUrls = new Set();
data.NEWS.forEach((n, i) => {
  const w = "NEWS[" + i + "] " + (n && n.title);
  checkStrings(n, ["region", "date", "title", "body", "why", "src", "url"], w);
  if (!REG.includes(n.region)) fail(w + ": region must be one of " + REG.join("/"));
  if (!DATE.test(n.date)) fail(w + ": date must look like '5 Nov 2026'");
  if (seenUrls.has(n.url)) fail(w + ": duplicate story url"); seenUrls.add(n.url);
  checkUrl(n.url, w);
});

// 4. The page's own defences must still be in place.
if (!/function esc\(s\)/.test(html)) fail("The esc() escaping function is missing");
if (!/function safeUrl\(u\)/.test(html)) fail("The safeUrl() link filter is missing");
const linkRenders = (html.match(/href="'\+(?!safeUrl\()/g) || []).length;
if (linkRenders) fail(linkRenders + " data link(s) rendered without safeUrl()");
if (!/rel="noopener/.test(html)) fail("External links are missing rel=noopener");

report();
function report() {
  if (warn.length) console.log("Warnings:\n - " + warn.join("\n - "));
  if (fails.length) {
    console.log("SECURITY CHECK FAILED (" + fails.length + "):\n - " + fails.join("\n - "));
    process.exit(1);
  }
  console.log("SECURITY CHECK PASSED: " + (data ? data.VULNS.length + " vulnerabilities, " + data.NEWS.length + " stories" : "") + ", page structure clean.");
  process.exit(0);
}
