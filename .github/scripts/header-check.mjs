// Checks that the live site sends the security headers set in vercel.json.
// Usage: node header-check.mjs <headers-file> <vercel.json>
// Prints problems and exits 1 if any header is missing or different.

import { readFileSync } from "node:fs";

const [headersFile, vercelFile] = process.argv.slice(2);
const raw = readFileSync(headersFile, "utf8").split(/\r?\n/);

// curl -D writes one block per response; use the last (final) one.
let block = [];
for (const line of raw) {
  if (/^HTTP\//i.test(line)) block = [];
  else if (line.includes(":")) block.push(line);
}
const live = new Map(block.map((l) => {
  const i = l.indexOf(":");
  return [l.slice(0, i).trim().toLowerCase(), l.slice(i + 1).trim()];
}));

const expected = JSON.parse(readFileSync(vercelFile, "utf8"))
  .headers.flatMap((h) => h.headers);

const problems = [];
for (const { key, value } of expected) {
  const got = live.get(key.toLowerCase());
  if (got === undefined) problems.push(`HEADER MISSING: ${key}`);
  else if (got !== value) problems.push(`HEADER CHANGED: ${key} is "${got}", expected "${value}"`);
}

if (problems.length) {
  console.log(problems.join("\n"));
  process.exit(1);
}
console.log(`HEADER CHECK PASSED: all ${expected.length} security headers present and correct.`);
