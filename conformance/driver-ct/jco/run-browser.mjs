// jco-browser driver for the ported conformance suites: both suites'
// case loops run inside headless Chromium via the upstream page driver
// — page, worker pool, stall watchdog, and Chrome ladder all live in
// @polymorph/component-test-js — and write results/jco-browser.jsonl +
// results/jco-browser-signing.jsonl. This file is the frame: core-URL
// enumeration, per-suite configuration, results writing.
//
// Gates in CI (the Actions runner image ships Chrome); locally it needs
// a Chrome/Chromium install and runs only when opted in with
// CONFORMANCE_BROWSER=1 (`just conformance-ct::all`), or directly with
// `just conformance-ct::run-browser`.
import { readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import {
  buildHarnessPage,
  findChrome,
  runPageHarness,
} from "@polymorph/component-test-js/browser-driver";
import { writeResultsFile } from "@polymorph/component-test-js/node-runner";

const REPO_ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const RESULTS_DIR = fileURLToPath(new URL("../results/", import.meta.url));
const BASE = "/conformance/driver-ct/jco";
// Stall bound for the driver's inactivity watchdog: the pool
// heartbeats per suite and per 25 rows, so quiet time is bounded by a
// batch of the slowest cases.
const STALL_TIMEOUT_MS = 90_000;

// The per-suite missing-features declarations are passed by the justfile
// (like jco-node's --missing), keeping them next to the jco-node ones and
// in sync with targets.toml / targets-signing.toml, which the aggregate
// cross-checks.
const { values } = parseArgs({
  options: {
    missing: { type: "string", default: "" },
    "missing-signing": { type: "string", default: "" },
    target: { type: "string", default: "jco-browser" },
  },
});

// Both suites run under one target key in their respective aggregates,
// so the report (and the results file) is keyed per entry.
const common = {
  target: values.target,
  importsUrl: `${BASE}/browser-imports.mjs`,
  // The driver's test-context (diagnostic sink wiring), not the
  // upstream default.
  contextUrl: `/conformance/driver-ct/context.js`,
};
const SUITES = [
  {
    ...common,
    key: "jco-browser",
    suite: "conformance-guest-ct",
    missing: values.missing.split(",").filter(Boolean),
  },
  {
    ...common,
    key: "jco-browser-signing",
    suite: "conformance-signing-guest-ct",
    missing: values["missing-signing"].split(",").filter(Boolean),
  },
];

// Resolve each suite's core-module list Node-side (the transpile emits
// however many cores the composition needs), so the page never fetches
// a missing file — a 404 would be tolerated but pollutes the console
// the driver mirrors.
for (const entry of SUITES) {
  const names = (await readdir(new URL("./generated/", import.meta.url))).sort();
  entry.moduleUrl = `${BASE}/generated/${entry.suite}.js`;
  entry.coreUrls = names
    .filter((n) => n.startsWith(`${entry.suite}.core`) && n.endsWith(".wasm"))
    .map((n) => `${BASE}/generated/${n}`);
}

const playwright = await import("playwright-core");
const outcome = await runPageHarness({
  playwright,
  engine: "chromium",
  executablePath: await findChrome(),
  repoRoot: REPO_ROOT,
  html: buildHarnessPage({
    title: "polymorph:webcrypto conformance (component-test stack)",
    config: { suites: SUITES },
  }),
  stallTimeoutMs: STALL_TIMEOUT_MS,
});

let failed = 0;
for (const { key } of SUITES) {
  const run = outcome[key];
  if (!run) throw new Error(`the page reported no run for ${key}`);
  const outPath = await writeResultsFile({ dir: RESULTS_DIR, target: key, lines: run.lines });
  const c = run.counts;
  process.stderr.write(
    `${values.target} ${key}: ${c.passed} passed, ${c.failed} failed, ` +
      `${c.skipped} skipped, ${c.na} not applicable, ${c.total} total ` +
      `(wrote ${outPath})\n`,
  );
  failed += c.failed;
}
process.exit(failed === 0 ? 0 : 1);
