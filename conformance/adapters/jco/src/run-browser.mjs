// The jco browser conformance adapter: serves the transpiled guests (shared
// and signing) and the browser-first host module over localhost, runs both
// corpora in headless Chromium (137+, which ships JSPI), and writes
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

// The in-page harness: mirrors run-node.mjs, driving both corpora — the
// shared guest and the host-only signing guest — in one page. The target's
// missing-features declaration is resolved Node-side from targets.toml and
// inlined (the page cannot import the Node-side helper).
const harness = (missing) => `<!doctype html>
<title>lann:webcrypto conformance</title>
<script type="module">
(async () => {
  try {
    const missing = ${JSON.stringify(missing)};
    const run = async (path) => {
      const { tests } = await import(path);
      const results = [];
      for (const testCase of tests.all(missing)) {
        const { tag, val } = await testCase.run();
        results.push({
          name: String(testCase.name()),
          features: Array.from(testCase.features(), String),
          outcome: String(tag),
          detail: String(val ?? ""),
        });
      }
      return results;
    };
    const shared = await run("/conformance/adapters/jco/generated/conformance-guest.js");
    const signing = await run(
      "/conformance/adapters/jco/generated-signing/conformance-signing-guest.js",
    );
    window.__report({ shared, signing });
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
