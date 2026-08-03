// Optimistic cross-engine ratchet transfer: apply one engine's loss-set
// *delta* to another engine's ratchet file, as set operations.
//
// The standing loss sets are per-engine facts and never transfer, but a
// shim change's *movement* is predominantly engine-generic — it moves
// tests whose round-trip outcome is decided in the shim/WIT layers before
// reaching the engine — so the delta usually does. The prediction is a
// guess with a safe verifier: the parity gate is two-sided (compare.mjs
// fails on unlisted losses *and* on listed losses not observed), so a
// wrong guess cannot pass — it fails on the next CI run exactly like a
// stale ratchet, and the fallback is the ordinary re-record
// (`just update-wpt-parity-webkit-from-ci`). A right guess is verified by
// that same run, so a green gate over a predicted file carries the same
// assurance as one over a recorded file.
//
// Where the prediction misses: a delta addition for a test the target
// engine's baseline fails natively (it cannot be a loss there — the
// engines' baselines diverge), and delta entries whose names differ
// between the engines' records (setup-failure renames). Both surface as
// gate failures, never as silent mispins.
//
// Usage: node predict.mjs <old-source.js> <new-source.js> <target.js>
//
// The delta is KNOWN_LOSSES(new-source) minus KNOWN_LOSSES(old-source) in
// both directions; the target file is rewritten in place.

import { pathToFileURL } from "node:url";
import { writeLosses } from "./losses-file.mjs";

const [oldSourcePath, newSourcePath, targetPath] = process.argv.slice(2);
if (!oldSourcePath || !newSourcePath || !targetPath || process.argv.length !== 5) {
  console.error("usage: node predict.mjs <old-source.js> <new-source.js> <target.js>");
  process.exit(2);
}

/** @param {string} path @returns {Promise<Set<string>>} */
async function losses(path) {
  const { KNOWN_LOSSES } = await import(pathToFileURL(path).href);
  return new Set(KNOWN_LOSSES);
}

const oldSource = await losses(oldSourcePath);
const newSource = await losses(newSourcePath);
const target = await losses(targetPath);

const added = [...newSource].filter((key) => !oldSource.has(key));
const removed = [...oldSource].filter((key) => !newSource.has(key));
if (added.length === 0 && removed.length === 0) {
  console.log("predict: the source ratchet has no delta; target unchanged");
  process.exit(0);
}

// Set operations are idempotent, but a delta entry the target already
// reflects is a sign the engines' movement diverged — report it so the
// diff review starts with the right expectations.
const alreadyPresent = added.filter((key) => target.has(key));
const absent = removed.filter((key) => !target.has(key));

const predicted = new Set(target);
for (const key of removed) predicted.delete(key);
for (const key of added) predicted.add(key);
writeLosses(targetPath, [...predicted]);

console.log(
  `predict: ${target.size} -> ${predicted.size} losses ` +
    `(+${added.length - alreadyPresent.length}, -${removed.length - absent.length})`,
);
if (alreadyPresent.length > 0) {
  console.log(`  ${alreadyPresent.length} added key(s) were already in the target:`);
  for (const key of alreadyPresent.slice(0, 10)) console.log(`    ${key}`);
}
if (absent.length > 0) {
  console.log(`  ${absent.length} removed key(s) were not in the target:`);
  for (const key of absent.slice(0, 10)) console.log(`    ${key}`);
}
console.log("review the diff, then let CI verify the guess (a miss fails the gate; fall back to `just update-wpt-parity-webkit-from-ci`)");
