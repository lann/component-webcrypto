// The browser WPT parity adapter: serves the repository root over
// localhost, runs both parity legs in a headless browser through the same
// legs module the parity page uses (js/componentize/wpt/web/legs.mjs), and
// writes the two record files the comparator consumes to ../build/
// (parity-baseline-<engine>.json, parity-roundtrip-<engine>.json).
//
// `--engine firefox` (default) or `--engine chromium` selects the browser:
// always Playwright's own build (pinned by playwright-core's version, so
// every run of one checkout measures one engine per name). Firefox is
// launched with Gecko's JSPI pref, which the round trip needs and Firefox
// has not yet shipped by default; Chromium ships JSPI. Install an engine
// once with `npx playwright-core install --with-deps <engine>` (from this
// directory).
import { createServer } from "node:http";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const OUT_DIR = join(REPO_ROOT, "js", "componentize", "wpt", "build");

const engineArgIndex = process.argv.indexOf("--engine");
const ENGINE = engineArgIndex === -1 ? "firefox" : process.argv[engineArgIndex + 1];
if (ENGINE !== "firefox" && ENGINE !== "chromium") {
  console.error("usage: node run-browser.mjs [--engine firefox|chromium]");
  process.exit(2);
}

const MIME = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".wasm": "application/wasm",
  ".map": "application/json",
};

// The in-page harness: both legs sequentially on the main thread (nothing
// here needs the page's worker), heartbeating per baseline group and per
// round-trip batch for the Node-side stall watchdog, reporting the two
// record arrays at the end.
const HARNESS = `<!doctype html>
<link rel="icon" href="data:,">
<title>lann:webcrypto WPT parity</title>
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

/** Serve the repository root (so legs.mjs, the suite bundles, and the
 *  transpiled runner's relative imports all resolve) plus the harness. */
function serve() {
  const server = createServer(async (req, res) => {
    const path = new URL(req.url, "http://localhost").pathname;
    if (path === "/") {
      res.writeHead(200, { "content-type": "text/html" });
      res.end(HARNESS);
      return;
    }
    try {
      const file = join(REPO_ROOT, path);
      const body = await readFile(file);
      res.writeHead(200, {
        "content-type": MIME[extname(file)] ?? "application/octet-stream",
      });
      res.end(body);
    } catch {
      res.writeHead(404);
      res.end("not found");
    }
  });
  return new Promise((resolveServer) => {
    server.listen(0, "127.0.0.1", () => resolveServer(server));
  });
}

// Watchdog bounds, matching the conformance browser adapter: launch and
// load get hard timeouts; the run is bounded by *inactivity*, since the
// harness heartbeats as results stream in.
const LAUNCH_TIMEOUT_MS = 120_000;
const LOAD_TIMEOUT_MS = 60_000;
const STALL_TIMEOUT_MS = 120_000;

async function main() {
  const [playwright, server] = await Promise.all([import("playwright-core"), serve()]);
  const { port } = server.address();

  const browser =
    ENGINE === "firefox"
      ? await playwright.firefox.launch({
          headless: true,
          timeout: LAUNCH_TIMEOUT_MS,
          firefoxUserPrefs: {
            "javascript.options.wasm_js_promise_integration": true,
          },
        })
      : await playwright.chromium.launch({
          headless: true,
          timeout: LAUNCH_TIMEOUT_MS,
        });
  try {
    const page = await browser.newPage();
    page.on("console", (msg) => {
      if (msg.type() === "error") console.error("[page]", msg.text());
    });

    let lastBeat = { at: Date.now(), note: "page created" };
    await page.exposeFunction("__progress", (note) => {
      lastBeat = { at: Date.now(), note: String(note) };
    });
    let settled = false;
    const report = new Promise((resolveReport, reject) => {
      page.exposeFunction("__report", resolveReport);
      page.on("crash", () =>
        reject(new Error(`page crashed (last heartbeat: ${lastBeat.note})`)),
      );
      page.on("pageerror", (err) =>
        reject(new Error(`uncaught page error: ${err} (last heartbeat: ${lastBeat.note})`)),
      );
      const watchdog = setInterval(() => {
        if (settled) {
          clearInterval(watchdog);
          return;
        }
        const stalled = Date.now() - lastBeat.at;
        if (stalled > STALL_TIMEOUT_MS) {
          clearInterval(watchdog);
          reject(
            new Error(
              `harness stalled: no heartbeat for ${Math.round(stalled / 1000)}s ` +
                `(last: ${lastBeat.note})`,
            ),
          );
        }
      }, 5_000);
      watchdog.unref?.();
    });

    await page.goto(`http://127.0.0.1:${port}/`, { timeout: LOAD_TIMEOUT_MS });
    const outcome = await report.finally(() => {
      settled = true;
    });
    if (outcome.error) throw new Error(`in-page harness failed: ${outcome.error}`);
    await mkdir(OUT_DIR, { recursive: true });
    await writeFile(join(OUT_DIR, `parity-baseline-${ENGINE}.json`), JSON.stringify(outcome.baseline));
    await writeFile(join(OUT_DIR, `parity-roundtrip-${ENGINE}.json`), JSON.stringify(outcome.roundtrip));
    console.log(
      `wpt parity (${ENGINE}): ${outcome.baseline.length} baseline records, ` +
        `${outcome.roundtrip.length} round-trip records`,
    );
  } finally {
    await browser.close();
    server.close();
  }
}

main().then(
  () => process.exit(0),
  (err) => {
    console.error(`wpt parity ${ENGINE} adapter failed:`, err);
    process.exit(1);
  },
);
