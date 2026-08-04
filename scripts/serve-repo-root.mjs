#!/usr/bin/env node
// Serve the repository root over localhost (dependency-free), so browser
// pages whose relative imports mirror the repository layout — today the
// WPT parity page (`just wpt::web`) — resolve their artifacts and the
// transpiled components' relative imports of js/jco/webcrypto.js.
// (Relocated from the retired conformance results viewer's
// conformance/web/serve.mjs at the M1.6 cutover.)
//
// PORT overrides the default port.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
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
  // Redirect the root to the parity page's directory (rather than
  // rewriting), so
  // the page's relative URLs resolve the same way they do on static hosts.
  if (path === "/") {
    res.writeHead(302, { location: "/js/componentize/wpt/web/" });
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
