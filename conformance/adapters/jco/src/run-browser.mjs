// The jco browser conformance adapter: serves the transpiled guests (shared
// and signing) and the browser-first host module over localhost, runs both
// suites in headless Chromium (137+, which ships JSPI), and writes
// `conformance/results/jco-browser.json` + `jco-browser-signing.json`.
// The serve/launch/watchdog machinery is the shared page driver
// (scripts/browser-page-driver.mjs).
//
// Gates in CI (the Actions runner image ships Chrome); locally it needs a
// Chrome/Chromium install — run it with CONFORMANCE_BROWSER=1 just
// conformance, or directly with `just conformance-jco-browser`.
import { access } from "node:fs/promises";
import { join } from "node:path";

import { runPageHarness } from "../../../../scripts/browser-page-driver.mjs";
import { missingFeatures, REPO_ROOT, writeReport } from "./report.mjs";

// The in-page harness: drives both suites — the shared guest and the
// host-only signing guest — through the results viewer's harness modules
// (conformance/web/harness.mjs + worker.mjs, served from the repo root), so
// the gating adapter and the page's live "test this browser" run share one
// driver *and* one worker pool (harness.mjs's runInWorkers): striped across
// parallel Web Workers, each with its own instances of the guests, falling
// back to a sequential main-thread run if the worker path fails. Results
// are re-sorted into suite order (workers interleave) before reporting. The
// target's missing-features declaration is resolved Node-side from
// targets.toml and inlined (the page cannot import the Node-side helper).
const harness = (missing) => `<!doctype html>
<link rel="icon" href="data:,">
<title>lann:webcrypto conformance</title>
<script type="module">
import { runAll, runInWorkers } from "/conformance/web/harness.mjs";

const missing = ${JSON.stringify(missing)};
const collected = { shared: [], signing: [] };

// Heartbeats for the Node-side stall watchdog: fire-and-forget (a closing
// page must not turn a heartbeat into an unhandled rejection), throttled to
// one per hundred results.
const beat = (note) => {
  try { window.__progress(note).catch(() => {}); } catch {}
};
let beats = 0;

const collect = (message) => {
  if (message.kind === "start") {
    beat("suite " + message.suite + ": " + message.total + " cases");
    return;
  }
  if (message.kind !== "result") return;
  const { suite, index, name, features, outcome, detail } = message;
  collected[suite].push({ index, name, features, outcome, detail });
  beats += 1;
  if (beats % 100 === 0) beat("result " + beats + ": " + suite + "/" + name);
};

(async () => {
  try {
    beat("starting worker run");
    const failure = await runInWorkers(missing, collect);
    if (failure !== null) {
      console.warn("worker run failed (" + failure + "); retrying on the main thread");
      beat("worker run failed; starting the main-thread fallback");
      collected.shared.length = 0;
      collected.signing.length = 0;
      await runAll(missing, collect);
    }
    for (const rows of Object.values(collected)) {
      rows.sort((a, b) => a.index - b.index);
      for (const row of rows) delete row.index;
    }
    window.__report({ shared: collected.shared, signing: collected.signing });
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
      "(e.g. `npx playwright install chromium`)",
  );
}

// Stall bound for the driver's inactivity watchdog: the harness heartbeats
// at least once per hundred results, so quiet time is bounded by a batch of
// the slowest cases.
const STALL_TIMEOUT_MS = 90_000;

async function main() {
  // Experimental: CONFORMANCE_ENGINE=firefox runs the same harness in
  // Playwright's Firefox (JSPI pref enabled) and reports as jco-firefox;
  // it never gates (targets.toml declares no such target).
  const engine = process.env.CONFORMANCE_ENGINE ?? "chromium";
  const missing = await missingFeatures("jco-browser");
  const playwright = await import("playwright-core");
  const outcome = await runPageHarness({
    playwright,
    engine,
    executablePath: engine === "chromium" ? await findChrome() : undefined,
    repoRoot: REPO_ROOT,
    html: harness(missing),
    stallTimeoutMs: STALL_TIMEOUT_MS,
  });
  const target = engine === "firefox" ? "jco-firefox" : "jco-browser";
  await writeReport(target, "shared", missing, outcome.shared);
  await writeReport(target, "signing", missing, outcome.signing, `${target}-signing`);
}

main().then(
  () => process.exit(0),
  (err) => {
    console.error("jco-browser adapter failed:", err);
    process.exit(1);
  },
);
