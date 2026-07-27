// Web Worker wrapper around the in-browser conformance harness: keeps the
// run off the main thread and streams results back via postMessage. The
// page spawns several of these, each running one shard of the corpus
// against its own instances of the guests.
import { runAll } from "./harness.mjs";

self.onmessage = async ({ data }) => {
  try {
    await runAll(data.missing, (message) => self.postMessage(message), data.shard);
    self.postMessage({ kind: "done" });
  } catch (err) {
    self.postMessage({ kind: "error", error: String(err?.stack ?? err) });
  }
};
