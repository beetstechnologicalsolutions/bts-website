// BTS website injection test: renders a copy of the page with hostile data
// and checks that none of it becomes live markup, script or a dangerous link.
// Usage: node xss-test.js <page.html>
"use strict";
const fs = require("fs");
const { JSDOM, VirtualConsole } = require("jsdom");

const html = fs.readFileSync(process.argv[2], "utf8");
const m = html.match(/\/\* DATA:START \*\/([\s\S]*?)\/\* DATA:END \*\//);
if (!m) { console.log("INJECTION TEST FAILED: data markers missing"); process.exit(1); }

const P = [
  '<img src=x onerror="window.__pwned=1">',
  '"><script>window.__pwned=1</script>',
  "'><svg onload=window.__pwned=1>",
  '<a href="javascript:window.__pwned=1">x</a>',
  '</span><iframe src="https://evil.example"></iframe>',
];
const hostile = `
var UPDATED=${JSON.stringify(P[0])};
var VULNS=[
 {id:"CVE-2026-00001",sev:"critical",score:"9.8",product:${JSON.stringify(P[0])},title:${JSON.stringify(P[1])},what:${JSON.stringify(P[2])},fix:${JSON.stringify(P[3])},added:${JSON.stringify(P[4])},src:${JSON.stringify(P[1])},url:"javascript:window.__pwned=1"},
 {id:"CVE-2026-00002",sev:"high",score:"8.1",product:"Safe product",title:"Safe title",what:"Safe text",fix:"Safe fix",added:"1 Nov 2026",src:"Safe",url:"https://example.com/a\\"onmouseover=\\"window.__pwned=1"},
 {id:"<b>bad-id</b>",sev:"critical",score:"9.9",product:"x",title:"x",what:"x",fix:"x",added:"x",src:"x",url:"https://example.com"}
];
var NEWS=[
 {region:"UK",date:"4 Nov 2026",title:${JSON.stringify(P[1])},body:${JSON.stringify(P[0])},why:${JSON.stringify(P[2])},src:${JSON.stringify(P[4])},url:"data:text/html,<script>window.__pwned=1</script>"},
 {region:"<img src=x onerror=window.__pwned=1>",date:"4 Nov 2026",title:"x",body:"x",why:"x",src:"x",url:"https://example.com"}
];
`;
// Layer 1: raw markup in the data must be rejected by the pre-publish check.
const path = require("path"), os = require("os"), { spawnSync } = require("child_process");
const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "bts-")), "hostile.html");
fs.writeFileSync(tmp, html.replace(m[0], "/* DATA:START */" + hostile + "/* DATA:END */"));
const gate = spawnSync(process.execPath, [path.join(__dirname, "security-check.js"), tmp], { encoding: "utf8" });
if (gate.status === 0) { console.log("INJECTION TEST FAILED: the security check let hostile data through"); process.exit(1); }

// Layer 2: even if markup arrives escaped (\u003c), the page must render it as text.
const escaped = hostile.replace(/</g, "\\u003c").replace(/>/g, "\\u003e");
const page = html.replace(m[0], "/* DATA:START */" + escaped + "/* DATA:END */");
const doc = "<!doctype html><html><head><meta charset=utf-8></head><body>" + page + "</body></html>";

const errors = [];
const vc = new VirtualConsole();
vc.on("jsdomError", e => errors.push(e.message));
const dom = new JSDOM(doc, { runScripts: "dangerously", pretendToBeVisual: true, url: "https://example.test/#news", virtualConsole: vc });
const w = dom.window;
w.matchMedia = w.matchMedia || (() => ({ matches: false, addListener() {}, removeListener() {} }));

setTimeout(() => {
  const d = w.document, fails = [];
  if (w.__pwned) fails.push("Injected script executed");
  const live = d.querySelectorAll("main iframe, main object, main embed, #tick-track img, #track img, #vuln-list img, #news-list img, main script, #tick-track script");
  if (live.length) fails.push(live.length + " injected element(s) became live markup");
  const evt = [...d.querySelectorAll("main *, header *")].filter(el => [...el.attributes].some(a => /^on/i.test(a.name)));
  if (evt.length) fails.push(evt.length + " element(s) carry injected event handlers");
  const bad = [...d.querySelectorAll("a[href]")].filter(a => /^\s*(javascript|data|vbscript):/i.test(a.getAttribute("href")));
  if (bad.length) fails.push(bad.length + " link(s) with javascript:/data: URLs");
  const quoted = [...d.querySelectorAll("a[href]")].filter(a => a.hasAttribute("onmouseover"));
  if (quoted.length) fails.push("A url broke out of its href attribute");
  if (d.querySelector("#vuln-list") && /bad-id/.test(d.querySelector("#vuln-list").innerHTML)) fails.push("A malformed entry (invalid CVE id) was rendered");
  const realErrors = errors.filter(e => !/Not implemented|scrollTo|showModal/.test(e));
  if (realErrors.length) fails.push("Page script errors: " + realErrors.join(" | "));
  if (fails.length) { console.log("INJECTION TEST FAILED:\n - " + fails.join("\n - ")); process.exit(1); }
  console.log("INJECTION TEST PASSED: hostile data was escaped, bad links neutralised, malformed entries dropped.");
  process.exit(0);
}, 400);
