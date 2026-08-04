// The Web Worker half of the jco-browser driver (run-browser.mjs): its
// own instance of the transpiled suite runs one shard of the case loop
// (harness.mjs — module workers cannot see the page's import map, which
// is why the transpile maps the wasi shim to relative paths), streaming
// each results-JSONL event back with its suite-order index, then the
// shard's counts. The browser counterpart of worker-node.mjs.
import { inventoryLookup, runCases } from "./harness.mjs";

// A rejection escaping the awaited chain (e.g. a platform quirk
// surfacing through the transpiled guest's async plumbing) would
// otherwise leave the worker silently wedged: unhandled rejections fire
// neither the catch below nor the page's worker.onerror.
self.onunhandledrejection = (event) => {
  event.preventDefault?.();
  self.postMessage({ kind: "error", error: String(event.reason?.stack ?? event.reason) });
};

self.onmessage = async ({ data }) => {
  const { suite, missing, cores, shard } = data;
  try {
    const coreModules = [];
    for (const core of cores) {
      const res = await fetch(new URL(`./generated/${core}`, import.meta.url));
      if (!res.ok) throw new Error(`fetching ${core}: ${res.status}`);
      coreModules.push(new Uint8Array(await res.arrayBuffer()));
    }
    const tagsOf = inventoryLookup(coreModules);
    const { tests } = await import(`./generated/${suite}.js`);
    const counts = await runCases({
      cases: await tests.all(),
      tagsOf,
      missing,
      shard,
      emit: (event, index) => self.postMessage({ kind: "event", index, event }),
    });
    delete counts.failures; // page-side detail; the rows carry it all
    self.postMessage({ kind: "counts", counts });
  } catch (err) {
    self.postMessage({ kind: "error", error: String(err?.stack ?? err) });
  }
};
