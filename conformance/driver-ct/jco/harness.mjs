// Shared core of the jco conformance drivers — the Node runner
// (runner.mjs) and the browser page harness (run-browser.mjs): the
// static tag inventory (custom sections of the transpiled core wasm),
// tag scheduling against a target's missing-features, and the per-case
// run loop producing results-JSONL event objects. Browser-safe by
// construction (no Node builtins; callers supply the core-wasm bytes
// and the transpiled suite module), so it is the lower layer — the
// incumbent's web/harness.mjs role, mirrored inside driver-ct/jco.
import { Context } from "../context.js";

export const TAGS_SECTION = "component-test:tags@0.1";

/** Custom sections named `wanted` from a core wasm module's bytes. */
export function customSections(bytes, wanted) {
  // core-module format: 4-byte magic, 4-byte version, then sections.
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let out = [];
  let off = 8;
  const uleb = () => {
    let result = 0, shift = 0, byte;
    do {
      byte = view.getUint8(off++);
      result |= (byte & 0x7f) << shift;
      shift += 7;
    } while (byte & 0x80);
    return result;
  };
  while (off < bytes.length) {
    const id = view.getUint8(off++);
    const size = uleb();
    const end = off + size;
    if (id === 0) {
      const start = off;
      const nameLen = uleb();
      const name = new TextDecoder().decode(bytes.subarray(off, off + nameLen));
      off += nameLen;
      if (name === wanted) out.push(bytes.subarray(off, end));
      off = start; // reset; jump via size below
    }
    off = end;
  }
  return out;
}

/**
 * Build the case-name → tags lookup from the tag inventory sections of
 * the given core modules' bytes. Throws if no inventory is found.
 * @param {Uint8Array[]} coreModules
 * @returns {(name: string) => string[] | undefined}
 */
export function inventoryLookup(coreModules) {
  const records = [];
  for (const bytes of coreModules) {
    for (const section of customSections(bytes, TAGS_SECTION)) {
      for (const line of new TextDecoder().decode(section).split("\n")) {
        if (!line.trim()) continue;
        const [name, ...tags] = line.split(" ").filter(Boolean);
        records.push({ name, tags });
      }
    }
  }
  if (records.length === 0) throw new Error("no tag inventory found in core wasm");
  const exact = new Map();
  const prefixes = [];
  for (const r of records) {
    if (r.name.endsWith("/*")) prefixes.push({ prefix: r.name.slice(0, -2), tags: r.tags });
    else exact.set(r.name, r.tags);
  }
  prefixes.sort((a, b) => b.prefix.length - a.prefix.length); // longest first
  return (name) => {
    if (exact.has(name)) return exact.get(name);
    const hit = prefixes.find((p) => name.startsWith(p.prefix + "/"));
    return hit ? hit.tags : undefined;
  };
}

/** Whether a case with these tags applies given the missing-features. */
export function applies(tags, missing) {
  return tags.every((t) =>
    t.startsWith("!") ? missing.includes(t.slice(1)) : !missing.includes(t)
  );
}

/** The results-JSONL envelope line for one target × suite run. The
 *  suite is named as its lockfile names it — the suite wasm's file
 *  stem (underscores) — not by the transpiled module's hyphenated
 *  name, so the aggregate's identity cross-check stays quiet. */
export function envelope(target, suite) {
  return {
    "component-test-results": "0.1",
    target,
    suite: { name: suite.replaceAll("-", "_") },
    run: { segment: 0 },
  };
}

/**
 * Run the suite's case loop: mark scheduling against `missing`, one
 * results-JSONL event object per case through `emit` (including the
 * not-applicable rows). Thrown on inventory drift (a case no tags
 * record covers) — the run is unsound, not failing.
 *
 * `shard` selects a stripe of the suite (case `i` belongs to shard
 * `i % count`), letting several workers — each with its own instance
 * of the transpiled suite — run disjoint slices concurrently. Striping
 * balances load better than contiguous chunks: expensive cases cluster
 * by algorithm. The default runs everything. `emit` receives the case's
 * suite-order index alongside the event so a sharded consumer can
 * restore suite order.
 *
 * @param {object} options
 * @param {Array} options.cases  `tests.all()` from the transpiled suite.
 * @param {(name: string) => string[] | undefined} options.tagsOf
 * @param {string[]} options.missing
 * @param {string} [options.only]  Substring filter (skips emit entirely).
 * @param {(event: object, index: number) => void} options.emit
 * @param {{ index: number, count: number }} [options.shard]
 * @returns {Promise<{passed, failed, skipped, na, total, failures}>}
 */
export async function runCases({ cases, tagsOf, missing, only, emit, shard }) {
  const { index: shardIndex, count: shardCount } = shard ?? { index: 0, count: 1 };
  let passed = 0, failed = 0, skipped = 0, na = 0, total = 0;
  const failures = [];
  for (const [caseIndex, testCase] of cases.entries()) {
    if (caseIndex % shardCount !== shardIndex) continue;
    total++;
    const name = String(testCase.name());
    if (only && !name.includes(only)) continue;
    const tags = tagsOf(name);
    if (tags === undefined) {
      throw new Error(`inventory drift: no tags record covers ${name}`);
    }
    if (!applies(tags, missing)) {
      na++;
      const excluding = tags.find((t) =>
        t.startsWith("!") ? !missing.includes(t.slice(1)) : missing.includes(t)
      );
      emit({ case: name, status: "not-applicable", detail: excluding ?? "" }, caseIndex);
      continue;
    }
    const diags = [];
    const ctx = new Context((msg) => diags.push(msg));
    let event;
    try {
      await testCase.run(ctx);
      passed++;
      event = { case: name, status: "pass", provenance: "returned" };
    } catch (e) {
      const payload = e?.payload ?? e;
      if (payload?.tag === "failed") {
        failed++;
        failures.push({ name, detail: payload.val, diags });
        event = { case: name, status: "fail", provenance: "returned", detail: payload.val };
      } else if (payload?.tag === "skipped") {
        skipped++;
        event = { case: name, status: "skipped", provenance: "returned", detail: payload.val };
      } else {
        failed++;
        const detail = `trap: ${e?.message ?? e}`;
        failures.push({ name, detail, diags });
        event = {
          case: name,
          status: "fail",
          provenance: "trap",
          detail,
          "diagnostics-complete": false,
        };
      }
    }
    if (diags.length > 0) event.diagnostics = diags;
    emit(event, caseIndex);
  }
  return { passed, failed, skipped, na, total, failures };
}

/**
 * Merge per-shard `runCases` counts. Shards partition the suite, so the
 * sums reproduce an unsharded run's counts exactly.
 */
export function mergeCounts(parts) {
  const out = { passed: 0, failed: 0, skipped: 0, na: 0, total: 0, failures: [] };
  for (const c of parts) {
    out.passed += c.passed;
    out.failed += c.failed;
    out.skipped += c.skipped;
    out.na += c.na;
    out.total += c.total;
    if (c.failures) out.failures.push(...c.failures);
  }
  return out;
}

/** The worker-pool size for this machine (the incumbent adapters' cap). */
export function workerCount(available) {
  return Math.max(1, Math.min(available ?? 1, 8));
}
