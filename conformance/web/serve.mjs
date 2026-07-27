#!/usr/bin/env node
// Serve the conformance results viewer (conformance/web/) over the
// repository root, so the page can fetch conformance/results/matrix.json
// and the transpiled guests can resolve their relative imports of
// jco-impl/webcrypto.js. Dependency-free; run it with `just conformance-web`
// (which produces the results and transpiled guests first).
//
// PORT overrides the default port.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const PORT = Number(process.env.PORT ?? 8787);

const MIME = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".json": "application/json",
  ".wasm": "application/wasm",
  ".map": "application/json",
};

const server = createServer(async (req, res) => {
  let path = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
  // Redirect the root to the viewer's directory (rather than rewriting), so
  // the page's relative URLs resolve the same way they do on static hosts.
  if (path === "/") {
    res.writeHead(302, { location: "/conformance/web/" });
    res.end();
    return;
  }
  if (path.endsWith("/")) path += "index.html";
  const file = resolve(join(REPO_ROOT, path));
  if (!file.startsWith(REPO_ROOT)) {
    res.writeHead(403);
    res.end("forbidden");
    return;
  }
  try {
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

server.listen(PORT, "127.0.0.1", () => {
  console.log(`conformance results viewer: http://127.0.0.1:${PORT}/`);
});
