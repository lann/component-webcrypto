// jco-node driver for the ported conformance suite. Sequential v1:
// reads the static tag inventory from the transpiled core wasm, applies
// the target manifest (--missing), runs applicable cases, and reports.
// The inventory parsing and case loop live in harness.mjs, shared with
// the browser driver (run-browser.mjs).
import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { envelope, inventoryLookup, runCases } from "./harness.mjs";

const { values } = parseArgs({
  options: {
    missing: { type: "string", default: "" },
    only: { type: "string" },
    jsonl: { type: "boolean", default: false },
    target: { type: "string", default: "jco-node" },
    suite: { type: "string", default: "conformance-guest-ct" },
  },
});
const suite = values.suite;
const missing = values.missing.split(",").filter(Boolean);
const jsonl = values.jsonl;

async function loadCoreModules() {
  const modules = [];
  for (const core of [`${suite}.core.wasm`, `${suite}.core2.wasm`]) {
    try {
      modules.push(new Uint8Array(await readFile(new URL(`./generated/${core}`, import.meta.url))));
    } catch {
      continue;
    }
  }
  return modules;
}

const tagsOf = inventoryLookup(await loadCoreModules());
if (jsonl) console.log(JSON.stringify(envelope(values.target, suite)));
const { tests } = await import(`./generated/${suite}.js`);

let counts;
try {
  counts = await runCases({
    cases: await tests.all(),
    tagsOf,
    missing,
    only: values.only,
    emit: (event) => {
      if (jsonl) console.log(JSON.stringify(event));
    },
  });
} catch (e) {
  console.error(String(e?.message ?? e));
  process.exit(2);
}
if (jsonl) console.log('{"segment-end":true}');

const { passed, failed, skipped, na, total, failures } = counts;
if (!jsonl) for (const f of failures.slice(0, 20)) {
  console.log(`FAIL: ${f.name}: ${f.detail}`);
  for (const d of f.diags) console.log(`    diag: ${d}`);
}
if (failures.length > 20) console.log(`... and ${failures.length - 20} more failures`);
if (!jsonl)
  console.log(
    `\nresult: ${passed} passed, ${failed} failed, ${skipped} skipped, ${na} not applicable, ${total} total`
  );
process.exit(failed === 0 ? 0 : 1);
