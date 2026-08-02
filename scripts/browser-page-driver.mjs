// Shared Playwright page driver for the repository's browser gates: the
// jco browser conformance adapter (conformance/adapters/jco/src/
// run-browser.mjs) and the WPT parity browser adapter (js/componentize/
// wpt/parity/run-browser.mjs). It serves the repository root over
// localhost with a caller-supplied harness page at "/", runs that page in
// a headless Playwright engine, and resolves with whatever the page
// reports.
//
// This module imports only Node builtins; the caller passes in its own
// playwright-core module, since each npm tree pins its own version.
//
// The page contract: the harness calls `window.__progress(note)` as work
// streams (the heartbeat the stall watchdog observes) and
// `window.__report(outcome)` exactly once at the end, with `{ error }`
// carrying an in-page failure.

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join, extname } from "node:path";

const MIME = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".wasm": "application/wasm",
  ".map": "application/json",
};

/** Serve `repoRoot` statically (so the transpiled guests' relative imports
 *  resolve) plus the harness page at "/". */
function serve(repoRoot, html) {
  const server = createServer(async (req, res) => {
    const path = new URL(req.url, "http://localhost").pathname;
    if (path === "/") {
      res.writeHead(200, { "content-type": "text/html" });
      res.end(html);
      return;
    }
    try {
      const file = join(repoRoot, path);
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
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

function launchBrowser(playwright, engine, executablePath, timeout) {
  if (engine === "firefox") {
    // Gecko's JSPI pref: the transpiled guests suspend on JSPI, which
    // Firefox has not yet shipped by default.
    return playwright.firefox.launch({
      headless: true,
      timeout,
      firefoxUserPrefs: {
        "javascript.options.wasm_js_promise_integration": true,
      },
    });
  }
  const options = { headless: true, timeout };
  if (executablePath !== undefined) options.executablePath = executablePath;
  return playwright[engine].launch(options);
}

/**
 * Run a harness page to completion and return what it reported.
 *
 * Watchdog bounds: browser launch and page load get hard timeouts; the run
 * itself is bounded by *inactivity* — the harness heartbeats as results
 * stream in, so a stall means the page hung (a wedged worker, a deadlocked
 * JSPI suspension, an uncaught error nothing was listening for), and the
 * watchdog fails fast with the last heartbeat naming where.
 * `stallTimeoutMs` is per-caller: the tolerable quiet time depends on the
 * harness's heartbeat cadence.
 *
 * @param {object} options
 * @param {object} options.playwright  The caller's playwright-core module.
 * @param {string} options.engine  "chromium" | "firefox" | "webkit".
 * @param {string} [options.executablePath]  A specific browser binary,
 *   instead of Playwright's own build of the engine.
 * @param {string} options.repoRoot  Directory the static server serves.
 * @param {string} options.html  The harness document served at "/".
 * @param {number} options.stallTimeoutMs  Max quiet time between heartbeats.
 * @param {number} [options.launchTimeoutMs]
 * @param {number} [options.loadTimeoutMs]
 * @returns {Promise<object>} The page's `__report` payload; throws if it
 *   carries `error`, if the page crashes or throws, or on a stall.
 */
export async function runPageHarness({
  playwright,
  engine,
  executablePath,
  repoRoot,
  html,
  stallTimeoutMs,
  launchTimeoutMs = 120_000,
  loadTimeoutMs = 60_000,
}) {
  const [browser, server] = await Promise.all([
    launchBrowser(playwright, engine, executablePath, launchTimeoutMs),
    serve(repoRoot, html),
  ]);
  try {
    const { port } = server.address();
    const page = await browser.newPage();
    page.on("console", (msg) => {
      if (msg.type() === "error") console.error("[page]", msg.text());
    });

    let lastBeat = { at: Date.now(), note: "page created" };
    await page.exposeFunction("__progress", (note) => {
      lastBeat = { at: Date.now(), note: String(note) };
    });
    let settled = false;
    const report = new Promise((resolve, reject) => {
      page.exposeFunction("__report", resolve);
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
        if (stalled > stallTimeoutMs) {
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

    await page.goto(`http://127.0.0.1:${port}/`, { timeout: loadTimeoutMs });
    const outcome = await report.finally(() => {
      settled = true;
    });
    if (outcome.error) throw new Error(`in-page harness failed: ${outcome.error}`);
    return outcome;
  } finally {
    await browser.close();
    server.close();
  }
}
