// BTS website tamper fingerprint.
// Fingerprints the whole page EXCEPT the news/vulnerability data block, so any change
// to wording, contact details, services, links, styles or code is caught.
//
//   node tests/fingerprint.js make  public/index.html                      prints a new fingerprint (JSON)
//   node tests/fingerprint.js check public/index.html tests/fingerprint.json  exits 0 if unchanged, 1 if not
"use strict";
const fs = require("fs");
const crypto = require("crypto");

function normalise(html) {
  let s = html.replace(/\r\n/g, "\n");
  const m = s.match(/\/\* DATA:START \*\/[\s\S]*?\/\* DATA:END \*\//);
  if (!m) throw new Error("DATA markers missing");
  s = s.replace(m[0], "/* DATA:START *//* DATA:END */");
  // The visible "updated" stamps are filled from data when the page loads.
  s = s.replace(/(<span class="upd">)[^<]*(<\/span>)/g, "$1$2");
  return s.trim();
}
const hash = (html) => crypto.createHash("sha256").update(normalise(html), "utf8").digest("hex");

const [mode, page, fp] = process.argv.slice(2);
if (!mode || !page) { console.error("Usage: node tests/fingerprint.js make|check <page.html> [fingerprint.json]"); process.exit(2); }
const html = fs.readFileSync(page, "utf8");

if (mode === "make") {
  console.log(JSON.stringify({ sha256: hash(html), bytes: normalise(html).length, made: new Date().toISOString() }, null, 2));
  process.exit(0);
}
if (mode === "check") {
  const want = JSON.parse(fs.readFileSync(fp, "utf8"));
  let got;
  try { got = hash(html); } catch (e) { console.log("TAMPER CHECK FAILED: " + e.message); process.exit(1); }
  if (got !== want.sha256) {
    console.log("TAMPER CHECK FAILED: the page outside the news data has changed since the approved fingerprint (" + want.made + ").");
    process.exit(1);
  }
  console.log("TAMPER CHECK PASSED: page matches the approved fingerprint (" + want.made + ").");
  process.exit(0);
}
console.error("Unknown mode " + mode); process.exit(2);
