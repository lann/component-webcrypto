// The jco browser conformance adapter: serves the transpiled guests (shared
// and signing) and the browser-first host module over localhost, runs both
// suites in headless Chromium (137+, which ships JSPI), and writes
// `conformance/results/jco-browser.json` + `jco-browser-signing.json`.
//
// Gates in CI (the Actions runner image ships Chrome); locally it needs a
// Chrome/Chromium install — run it with CONFORMANCE_BROWSER=1 just
// conformance, or directly with `just conformance-jco-browser`.
import { createServer } from "node:http";
import { readFile, access } from "node:fs/promises";
import { join, extname } from "node:path";

import { missingFeatures, REPO_ROOT, writeReport } from "./report.mjs";

const MIME = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".wasm": "application/wasm",
  ".map": "application/json",
};

// The in-page harness: drives both suites — the shared guest and the
// host-only signing guest — through the results viewer's harness modules
// (conformance/web/harness.mjs + worker.mjs, served from the repo root), so
// the gating adapter and the page's live "test this browser" run share one
// driver: striped across parallel Web Workers, each with its own instances
// of the guests, falling back to a sequential main-thread run if the worker
// path fails. Results are re-sorted into suite order (workers interleave)
// before reporting. The target's missing-features declaration is resolved
// Node-side from targets.toml and inlined (the page cannot import the
// Node-side helper).
const harness = (missing) => `<!doctype html>
<link rel="icon" href="data:,">
<title>lann:webcrypto conformance</title>
<script type="module">
import { runAll } from "/conformance/web/harness.mjs";

const missing = ${JSON.stringify(missing)};
const collected = { shared: [], signing: [] };

const collect = (message) => {
  if (message.kind !== "result") return;
  const { suite, index, name, features, outcome, detail } = message;
  collected[suite].push({ index, name, features, outcome, detail });
};

/** Run one suite stripe per worker; resolve to null on success or the
 *  first failure (any worker failing aborts them all). */
const runInWorkers = (count) =>
  new Promise((resolve) => {
    const workers = [];
    let done = 0;
    let settled = false;
    const settle = (failure) => {
      if (settled) return;
      settled = true;
      for (const worker of workers) worker.terminate();
      resolve(failure);
    };
    for (let index = 0; index < count; index += 1) {
      let worker;
      try {
        worker = new Worker("/conformance/web/worker.mjs", { type: "module" });
      } catch (err) {
        settle(String(err));
        return;
      }
      worker.onmessage = ({ data }) => {
        if (settled) return;
        if (data.kind === "error") settle(data.error);
        else if (data.kind === "done") {
          done += 1;
          if (done === count) settle(null);
        } else collect(data);
      };
      worker.onerror = (event) => {
        settle(String(event.message ?? "worker failed to start"));
      };
      worker.postMessage({ missing, shard: { index, count } });
      workers.push(worker);
    }
  });

(async () => {
  try {
    const failure = await runInWorkers(
      Math.min(navigator.hardwareConcurrency || 2, 8),
    );
    if (failure !== null) {
      console.warn("worker run failed (" + failure + "); retrying on the main thread");
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

/** Serve the repository root (so the guests' relative imports of
 *  jco-impl/webcrypto.js resolve) plus the harness page. */
function serve(page) {
  const server = createServer(async (req, res) => {
    const path = new URL(req.url, "http://localhost").pathname;
    if (path === "/") {
      res.writeHead(200, { "content-type": "text/html" });
      res.end(page);
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
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

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

async function main() {
  const missing = await missingFeatures("jco-browser");
  const [{ chromium }, server, executablePath] = await Promise.all([
    import("playwright-core"),
    serve(harness(missing)),
    findChrome(),
  ]);
  const { port } = server.address();

  const browser = await chromium.launch({ executablePath, headless: true });
  try {
    const page = await browser.newPage();
    page.on("console", (msg) => {
      if (msg.type() === "error") console.error("[page]", msg.text());
    });
    const report = new Promise((resolve) => {
      page.exposeFunction("__report", resolve);
    });
    await page.goto(`http://127.0.0.1:${port}/`);
    const outcome = await report;
    if (outcome.error) throw new Error(`in-page harness failed: ${outcome.error}`);
    await writeReport("jco-browser", "shared", missing, outcome.shared);
    await writeReport("jco-browser", "signing", missing, outcome.signing, "jco-browser-signing");
  } finally {
    await browser.close();
    server.close();
  }
}

main().then(
  () => process.exit(0),
  (err) => {
    console.error("jco-browser adapter failed:", err);
    process.exit(1);
  },
);
