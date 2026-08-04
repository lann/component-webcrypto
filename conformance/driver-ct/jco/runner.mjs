// jco-node driver for the ported conformance suite. Sequential v1:
// reads the static tag inventory from the transpiled core wasm, applies
// the target manifest (--missing), runs applicable cases, and reports.
import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { Context } from "../context.js";

const { values } = parseArgs({
  options: {
    missing: { type: "string", default: "" },
    only: { type: "string" },
    jsonl: { type: "boolean", default: false },
    target: { type: "string", default: "jco-node" },
    suite: { type: "string", default: "conformance-guest-ct" },
  },
});
const suite = values.suite;
const missing = values.missing.split(",").filter(Boolean);
const jsonl = values.jsonl;

// ---- static tag inventory: custom sections from the core modules
const TAGS_SECTION = "component-test:tags@0.1";

function customSections(bytes, wanted) {
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

async function loadInventory() {
  const records = [];
  for (const core of [`${suite}.core.wasm`, `${suite}.core2.wasm`]) {
    let bytes;
    try {
      bytes = new Uint8Array(await readFile(new URL(`./generated/${core}`, import.meta.url)));
    } catch {
      continue;
    }
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

function applies(tags, missing) {
  return tags.every((t) =>
    t.startsWith("!") ? missing.includes(t.slice(1)) : !missing.includes(t)
  );
}

// ---- run
const tagsOf = await loadInventory();
if (jsonl) {
  console.log(
    JSON.stringify({
      "component-test-results": "0.1",
      target: values.target,
      suite: { name: suite },
      run: { segment: 0 },
    })
  );
}
const { tests } = await import(`./generated/${suite}.js`);

const cases = await tests.all();
let passed = 0, failed = 0, skipped = 0, na = 0;
const failures = [];

for (const testCase of cases) {
  const name = String(testCase.name());
  if (values.only && !name.includes(values.only)) continue;
  const tags = tagsOf(name);
  if (tags === undefined) {
    console.error(`inventory drift: no tags record covers ${name}`);
    process.exit(2);
  }
  if (!applies(tags, missing)) {
    na++;
    if (jsonl) {
      const excluding = tags.find((t) =>
        t.startsWith("!") ? !missing.includes(t.slice(1)) : missing.includes(t)
      );
      console.log(
        JSON.stringify({
          case: name,
          status: "not-applicable",
          detail: excluding ?? "",
        })
      );
    }
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
  if (jsonl) {
    if (diags.length > 0) event.diagnostics = diags;
    console.log(JSON.stringify(event));
  }
}
if (jsonl) console.log('{"segment-end":true}');

if (!jsonl) for (const f of failures.slice(0, 20)) {
  console.log(`FAIL: ${f.name}: ${f.detail}`);
  for (const d of f.diags) console.log(`    diag: ${d}`);
}
if (failures.length > 20) console.log(`... and ${failures.length - 20} more failures`);
if (!jsonl)
  console.log(
    `\nresult: ${passed} passed, ${failed} failed, ${skipped} skipped, ${na} not applicable, ${cases.length} total`
  );
process.exit(failed === 0 ? 0 : 1);
