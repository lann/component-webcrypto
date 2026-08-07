// The Web Worker half of the jco-browser driver (run-browser.mjs): its
// own instance of the transpiled suite runs one shard of the case loop,
// streaming each results-JSONL event back with its suite-order index,
// then the shard's counts. The browser counterpart of worker-node.mjs.
// Relative specifiers throughout: module workers cannot see the page's
// import map, so the wasi shim (browser build), the harness core, and
// the host module all resolve by path.
import { inventoryLookup, runCases } from "./node_modules/@polymorph/component-test-js/js/viewer/harness.mjs";
import * as cli from "./node_modules/@bytecodealliance/preview2-shim/lib/browser/cli.js";
import * as clocks from "./node_modules/@bytecodealliance/preview2-shim/lib/browser/clocks.js";
import * as io from "./node_modules/@bytecodealliance/preview2-shim/lib/browser/io.js";
import * as random from "./node_modules/@bytecodealliance/preview2-shim/lib/browser/random.js";
import * as filesystem from "./node_modules/@bytecodealliance/preview2-shim/lib/browser/filesystem.js";
import { Context } from "../context.js";
import { instantiateSuite } from "./host-imports.mjs";

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
    const coreBytes = [];
    const modules = new Map();
    for (const core of cores) {
      const res = await fetch(new URL(`./generated/${core}`, import.meta.url));
      if (!res.ok) throw new Error(`fetching ${core}: ${res.status}`);
      const bytes = new Uint8Array(await res.arrayBuffer());
      coreBytes.push(bytes);
      modules.set(core, await WebAssembly.compile(bytes));
    }
    const tagsOf = inventoryLookup(coreBytes);
    const { instantiate } = await import(`./generated/${suite}.js`);
    const tests = await instantiateSuite({
      instantiate,
      modules,
      wasi: { cli, clocks, io, random, filesystem },
    });
    const counts = await runCases({
      cases: await tests.all(),
      Context,
      tagsOf,
      missing,
      shard,
      emit: (event, index) => self.postMessage({ kind: "event", index, event }),
    });
    self.postMessage({ kind: "counts", counts });
  } catch (err) {
    self.postMessage({ kind: "error", error: String(err?.stack ?? err) });
  }
};
