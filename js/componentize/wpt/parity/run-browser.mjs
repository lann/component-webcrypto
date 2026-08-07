// The browser WPT parity adapter: serves the repository root over
// localhost, runs both parity legs in a headless browser through the same
// legs module the parity page uses (js/componentize/wpt/web/legs.mjs), and
// writes the two record files the comparator consumes to ../build/
// (parity-baseline-<engine>.json, parity-roundtrip-<engine>.json).
// The serve/launch/watchdog machinery is the shared page driver
// (@polymorph/component-test-js/browser-driver).
//
// `--engine firefox` (default) or `--engine chromium` selects the browser:
// always Playwright's own build (pinned by playwright-core's version, so
// every run of one checkout measures one engine per name). Firefox is
// launched with Gecko's JSPI pref, which the round trip needs and Firefox
// has not yet shipped by default; Chromium ships JSPI. Install an engine
// once with `npx playwright-core install --with-deps <engine>` (from this
// directory).
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { runPageHarness } from "@polymorph/component-test-js/browser-driver";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const OUT_DIR = join(REPO_ROOT, "js", "componentize", "wpt", "build");

const engineArgIndex = process.argv.indexOf("--engine");
const ENGINE = engineArgIndex === -1 ? "firefox" : process.argv[engineArgIndex + 1];
if (ENGINE !== "firefox" && ENGINE !== "chromium" && ENGINE !== "webkit") {
  console.error("usage: node run-browser.mjs [--engine firefox|chromium|webkit]");
  process.exit(2);
}

// The in-page harness: both legs sequentially on the main thread (nothing
// here needs the page's worker), heartbeating per baseline group and per
// round-trip batch for the Node-side stall watchdog, reporting the two
// record arrays at the end.
const HARNESS = `<!doctype html>
<link rel="icon" href="data:,">
<title>polymorph:webcrypto WPT parity</title>
<script type="module">
import { runBaselineLeg, runRoundtripLeg } from "/js/componentize/wpt/web/legs.mjs";

const beat = (note) => {
  try { window.__progress(note).catch(() => {}); } catch {}
};

(async () => {
  try {
    if (typeof WebAssembly.Suspending !== "function") {
      throw new Error("no JSPI in this browser (for Firefox, is the Gecko pref applied?)");
    }
    const baseline = [];
    let groups = 0;
    await runBaselineLeg((group, results) => {
      groups += 1;
      beat("baseline group " + groups + ": " + group);
      for (const { name, status, message } of results) {
        baseline.push(message === undefined ? { group, name, status } : { group, name, status, message });
      }
    });
    const roundtrip = [];
    beat("round trip starting");
    await runRoundtripLeg((records) => {
      roundtrip.push(...records);
      beat("round trip: " + roundtrip.length + " records");
    });
    window.__report({ baseline, roundtrip });
  } catch (err) {
    window.__report({ error: String(err?.stack ?? err) });
  }
})();
</script>`;

// Stall bound for the driver's inactivity watchdog: this harness heartbeats
// only per baseline group and per round-trip batch — coarser than the
// conformance adapter's per-results cadence, hence a looser bound.
const STALL_TIMEOUT_MS = 120_000;

async function main() {
  const playwright = await import("playwright-core");
  const outcome = await runPageHarness({
    playwright,
    engine: ENGINE,
    repoRoot: REPO_ROOT,
    html: HARNESS,
    stallTimeoutMs: STALL_TIMEOUT_MS,
  });
  await mkdir(OUT_DIR, { recursive: true });
  await writeFile(join(OUT_DIR, `parity-baseline-${ENGINE}.json`), JSON.stringify(outcome.baseline));
  await writeFile(join(OUT_DIR, `parity-roundtrip-${ENGINE}.json`), JSON.stringify(outcome.roundtrip));
  console.log(
    `wpt parity (${ENGINE}): ${outcome.baseline.length} baseline records, ` +
      `${outcome.roundtrip.length} round-trip records`,
  );
}

main().then(
  () => process.exit(0),
  (err) => {
    console.error(`wpt parity ${ENGINE} adapter failed:`, err);
    process.exit(1);
  },
);
