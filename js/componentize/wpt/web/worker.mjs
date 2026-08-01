// Web Worker wrapper around the parity legs (legs.mjs): keeps both runs
// off the main thread and streams results back via postMessage. The page
// falls back to running legs.mjs on the main thread if this path fails.
import { runBaselineLeg, runRoundtripLeg } from "./legs.mjs";

// A rejection escaping the awaited chain (e.g. a platform quirk surfacing
// through the transpiled runner's async plumbing) would otherwise leave
// the worker silently wedged: unhandled rejections fire neither the catch
// below nor the page's worker.onerror. Report it as the run's failure.
self.onunhandledrejection = (event) => {
  event.preventDefault?.();
  self.postMessage({
    kind: "error",
    error: String(event.reason?.stack ?? event.reason),
  });
};

self.onmessage = async ({ data }) => {
  try {
    await runBaselineLeg((group, results) => {
      self.postMessage({ kind: "baseline-group", group, results });
    });
    if (data.runRoundtrip) {
      self.postMessage({ kind: "roundtrip-start" });
      const count = await runRoundtripLeg((records) => {
        self.postMessage({ kind: "roundtrip-records", records });
      });
      self.postMessage({ kind: "roundtrip-done", count });
    }
    self.postMessage({ kind: "done" });
  } catch (err) {
    self.postMessage({ kind: "error", error: String(err?.stack ?? err) });
  }
};
