// Web Worker wrapper around the in-browser conformance harness: keeps the
// run off the main thread and streams results back via postMessage. The
// page spawns several of these, each running one shard of the suites
// against its own instances of the guests.
import { runAll } from "./harness.mjs";

// A rejection escaping the awaited chain (e.g. a platform quirk surfacing
// through the transpiled guest's async plumbing) would otherwise leave the
// worker silently wedged: unhandled rejections fire neither the catch below
// nor the page's worker.onerror. Report it as the run's failure.
self.onunhandledrejection = (event) => {
  event.preventDefault?.();
  self.postMessage({
    kind: "error",
    error: String(event.reason?.stack ?? event.reason),
  });
};

self.onmessage = async ({ data }) => {
  try {
    await runAll(data.missing, (message) => self.postMessage(message), data.shard);
    self.postMessage({ kind: "done" });
  } catch (err) {
    self.postMessage({ kind: "error", error: String(err?.stack ?? err) });
  }
};
