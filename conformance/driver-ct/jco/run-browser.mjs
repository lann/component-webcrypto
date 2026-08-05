// jco-browser driver for the ported conformance suites: serves the
// repository root over localhost (so the transpiled guests' relative
// imports of js/jco/webcrypto.js and the driver's context.js resolve),
// runs both suites' case loops inside headless Chromium via the shared
// page harness (harness.mjs, the same module runner.mjs drives under
// Node), and writes results/jco-browser.jsonl +
// results/jco-browser-signing.jsonl.
//
// Gates in CI (the Actions runner image ships Chrome); locally it needs
// a Chrome/Chromium install and runs only when opted in with
// CONFORMANCE_BROWSER=1 (`just conformance-ct::all`), or directly with
// `just conformance-ct::run-browser`.
import { access, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import { runPageHarness } from "../../../scripts/browser-page-driver.mjs";
import { envelope } from "@polymorph/component-test-js/harness";

const REPO_ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const RESULTS_DIR = fileURLToPath(new URL("../results/", import.meta.url));

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

const SUITES = [
  {
    suite: "conformance-guest-ct",
    missing: values.missing.split(",").filter(Boolean),
    out: "jco-browser.jsonl",
  },
  {
    suite: "conformance-signing-guest-ct",
    missing: values["missing-signing"].split(",").filter(Boolean),
    out: "jco-browser-signing.jsonl",
  },
];

// Resolve each suite's core-module list Node-side (the transpile emits
// one or two cores), so the page never fetches a missing file — a 404
// would be tolerated but pollutes the console the driver mirrors.
for (const entry of SUITES) {
  entry.cores = [];
  for (const core of [`${entry.suite}.core.wasm`, `${entry.suite}.core2.wasm`]) {
    try {
      await access(new URL(`./generated/${core}`, import.meta.url));
      entry.cores.push(core);
    } catch {
      // Not emitted by this transpile.
    }
  }
}

// The in-page harness: spawns a pool of module Web Workers
// (worker-browser.mjs), each running one shard of a suite's case loop
// with its own instance of the transpiled suite (whose polymorph:webcrypto
// imports resolve to js/jco/webcrypto.js — the browser-first host,
// feature-detecting per call — and whose wasi imports resolve to
// relative paths into the preview2-shim browser build, mapped at
// transpile time: module workers cannot see a page's import map).
// Rows come back tagged with their suite-order index and are re-sorted
// before reporting.
//
// Heartbeats feed the Node-side stall watchdog: fire-and-forget (a
// closing page must not turn a heartbeat into an unhandled rejection),
// throttled to one per twenty-five rows.
const BASE = "/conformance/driver-ct/jco";
const harness = (suites) => `<!doctype html>
<link rel="icon" href="data:,">
<title>polymorph:webcrypto conformance (component-test stack)</title>
<script type="module">
import { mergeCounts, workerCount } from "${BASE}/node_modules/@polymorph/component-test-js/js/viewer/harness.mjs";

const suites = ${JSON.stringify(suites)};
const jobs = workerCount(navigator.hardwareConcurrency ?? 4);
const beat = (note) => {
  try { window.__progress(note).catch(() => {}); } catch {}
};
let rows = 0;

// One shard of one suite: a fresh worker running its stripe to
// completion. Workers are per-shard (not reused across suites) so each
// suite gets fresh instances, as the sequential harness had.
const runShard = (suite, missing, cores, shard) =>
  new Promise((resolve, reject) => {
    const worker = new Worker("${BASE}/worker-browser.mjs", { type: "module" });
    const events = [];
    worker.onmessage = ({ data }) => {
      if (data.kind === "event") {
        events.push(data);
        rows += 1;
        if (rows % 25 === 0) beat("row " + rows + ": " + data.event.case);
      } else if (data.kind === "counts") {
        worker.terminate();
        resolve({ events, counts: data.counts });
      } else {
        worker.terminate();
        reject(new Error("worker (shard " + shard.index + "): " + data.error));
      }
    };
    worker.onerror = (e) => {
      worker.terminate();
      reject(new Error("worker (shard " + shard.index + "): " + (e.message ?? e)));
    };
    worker.postMessage({ suite, missing, cores, shard });
  });

(async () => {
  try {
    const out = {};
    for (const { suite, missing, cores } of suites) {
      beat("suite " + suite + ": " + jobs + " workers");
      const shards = await Promise.all(
        Array.from({ length: jobs }, (_, index) =>
          runShard(suite, missing, cores, { index, count: jobs })
        )
      );
      const events = shards.flatMap((s) => s.events);
      events.sort((a, b) => a.index - b.index);
      out[suite] = {
        events: events.map((e) => e.event),
        counts: mergeCounts(shards.map((s) => s.counts)),
      };
    }
    window.__report(out);
  } catch (err) {
    window.__report({ error: String(err?.stack ?? err) });
  }
})();
</script>`;

/** Locate a Chromium/Chrome binary: CHROME_PATH, common system names, then
 *  the Playwright browser cache. */
async function findChrome() {
  const { env } = process;
  const candidates = [];
  if (env.CHROME_PATH) candidates.push(env.CHROME_PATH);
  for (const name of ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"]) {
    for (const dir of ["/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"]) {
      candidates.push(join(dir, name));
    }
  }
  const cache = join(env.HOME ?? "", ".cache", "ms-playwright");
  try {
    const { readdir } = await import("node:fs/promises");
    for (const entry of (await readdir(cache)).sort().reverse()) {
      if (entry.startsWith("chromium_headless_shell-")) {
        candidates.push(join(cache, entry, "chrome-linux", "headless_shell"));
      } else if (entry.startsWith("chromium-")) {
        candidates.push(join(cache, entry, "chrome-linux", "chrome"));
      }
    }
  } catch {
    // No playwright cache.
  }
  for (const candidate of candidates) {
    try {
      await access(candidate);
      return candidate;
    } catch {
      // Try the next candidate.
    }
  }
  throw new Error(
    "no Chromium/Chrome binary found: set CHROME_PATH or install one " +
      "(e.g. `npx playwright-core install chromium`)",
  );
}

// Stall bound for the driver's inactivity watchdog: the harness
// heartbeats at least once per twenty-five rows, so quiet time is
// bounded by a batch of the slowest cases.
const STALL_TIMEOUT_MS = 90_000;

async function main() {
  const playwright = await import("playwright-core");
  const outcome = await runPageHarness({
    playwright,
    engine: "chromium",
    executablePath: await findChrome(),
    repoRoot: REPO_ROOT,
    html: harness(SUITES),
    stallTimeoutMs: STALL_TIMEOUT_MS,
  });

  await mkdir(RESULTS_DIR, { recursive: true });
  let failed = 0;
  for (const { suite, out } of SUITES) {
    const run = outcome[suite];
    if (!run) throw new Error(`the page reported no run for suite ${suite}`);
    const lines = [
      JSON.stringify(envelope(values.target, suite.replaceAll("-", "_"))), // lockfile identity: wasm file stem
      ...run.events.map((event) => JSON.stringify(event)),
      '{"segment-end":true}',
    ];
    await writeFile(join(RESULTS_DIR, out), lines.join("\n") + "\n");
    const c = run.counts;
    console.error(
      `${values.target} ${suite}: ${c.passed} passed, ${c.failed} failed, ` +
        `${c.skipped} skipped, ${c.na} not applicable, ${c.total} total ` +
        `(wrote results/${out})`,
    );
    failed += c.failed;
  }
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error("jco-browser driver failed:", err);
  process.exit(1);
});
