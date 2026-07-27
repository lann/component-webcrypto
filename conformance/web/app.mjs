// The conformance results viewer: renders the cross-target matrix emitted
// by the conformance runner (`--json-out`) as a collapsing tree — rows are
// test cases grouped by the `/` segments of their names, columns are
// targets — and drives a live run of the same corpus against *this*
// browser's WebCrypto via the transpiled guests (see harness.mjs).
import { runAll } from "./harness.mjs";

// Resolved relative to this module, so the viewer works from any base path
// (the local server's repo root, or a GitHub Pages project subpath).
const DATA_URL = new URL("../results/matrix.json", import.meta.url);
const JSPI_SUPPORT_URL = "https://caniuse.com/wf-wasm-jspi";
// The browser column reuses this target's missing-features declaration:
// any WebCrypto browser is missing the same features.
const BROWSER_TARGET = "jco-browser";
const CODE = { pass: "p", fail: "f", skipped: "s" };
const GLYPH = { p: ["✓", "pass"], f: ["✗", "fail"], s: ["skip", "skip"] };
// Cap on paths auto-expanded to failing leaves at load.
const AUTO_EXPAND_LIMIT = 50;

const el = (id) => document.getElementById(id);

function warn(message) {
  const div = document.createElement("div");
  div.className = "warning";
  div.textContent = message;
  el("warnings").append(div);
}

// --- model -------------------------------------------------------------

/** A tree node; leaves hold the index of their case in `data.cases`. */
function makeNode(label, parent) {
  return {
    label,
    parent,
    depth: parent ? parent.depth + 1 : 0,
    children: new Map(),
    caseIndex: null,
    // One {p, f, s} per static target column, plus one for "this browser".
    counts: null,
    row: null,
    liveCell: null,
    expanded: false,
    rendered: false,
  };
}

function buildModel(data) {
  const targets = Object.keys(data.targets);
  const columns = targets.length + 1; // + "this browser"
  const zero = () => ({ p: 0, f: 0, s: 0 });

  const root = makeNode("all cases", null);
  root.counts = Array.from({ length: columns }, zero);
  const leaves = [];
  const indexByName = new Map();
  data.cases.forEach((c, i) => {
    indexByName.set(c.name, i);
    let node = root;
    for (const segment of c.name.split("/")) {
      let child = node.children.get(segment);
      if (!child) {
        child = makeNode(segment, node);
        child.counts = Array.from({ length: columns }, zero);
        node.children.set(segment, child);
      }
      node = child;
    }
    node.caseIndex = i;
    leaves.push(node);
  });

  // Static rollups.
  targets.forEach((target, column) => {
    const outcomes = data.outcomes[target] ?? [];
    outcomes.forEach((code, i) => {
      if (code === null || code === undefined) return;
      for (let node = leaves[i]; node; node = node.parent) {
        node.counts[column][code] += 1;
      }
    });
  });

  return {
    data,
    targets,
    liveColumn: targets.length,
    root,
    leaves,
    indexByName,
    liveOutcomes: new Array(data.cases.length).fill(null),
    liveDetails: new Array(data.cases.length).fill(""),
  };
}

// --- rendering -----------------------------------------------------------

function branchCell(cell, counts) {
  const ran = counts.p + counts.f + counts.s;
  if (ran === 0) {
    cell.textContent = "—";
    cell.className = "none";
    cell.removeAttribute("title");
    return;
  }
  let text = `${counts.p}/${ran}`;
  if (counts.f > 0) text += ` ✗${counts.f}`;
  if (counts.s > 0) text += ` ⊘${counts.s}`;
  cell.textContent = text;
  cell.className = counts.f > 0 ? "fail" : counts.s > 0 ? "skip" : "pass";
  cell.title = `${counts.p} passed, ${counts.f} failed, ${counts.s} skipped`;
}

function leafCell(cell, code, detail) {
  if (code === null || code === undefined) {
    cell.textContent = "—";
    cell.className = "none";
    return;
  }
  const [glyph, cls] = GLYPH[code] ?? [code, "none"];
  cell.textContent = glyph;
  cell.className = cls;
  if (detail) cell.title = detail;
}

function updateLiveCell(model, node) {
  if (!node.liveCell) return;
  if (node.caseIndex !== null) {
    leafCell(
      node.liveCell,
      model.liveOutcomes[node.caseIndex],
      model.liveDetails[node.caseIndex],
    );
  } else {
    branchCell(node.liveCell, node.counts[model.liveColumn]);
  }
}

/** Create (once) the `<tr>` for a node and fill its static cells. */
function renderRow(model, node) {
  const row = document.createElement("tr");
  row.className = node.caseIndex === null ? "branch" : "leaf";
  const name = document.createElement("td");
  name.className = "name";
  name.style.paddingLeft = `${0.6 + (node.depth - 1) * 1.1}em`;
  const toggle = document.createElement("span");
  toggle.className = "toggle";
  toggle.textContent = node.caseIndex === null ? "▸" : "";
  name.append(toggle, node.label);
  row.append(name);

  model.targets.forEach((target, column) => {
    const cell = document.createElement("td");
    if (node.caseIndex === null) {
      branchCell(cell, node.counts[column]);
    } else {
      leafCell(
        cell,
        model.data.outcomes[target]?.[node.caseIndex],
        model.data.details[target]?.[String(node.caseIndex)],
      );
    }
    row.append(cell);
  });
  const live = document.createElement("td");
  node.liveCell = live;
  row.append(live);

  node.row = row;
  node.rendered = true;
  updateLiveCell(model, node);
  if (node.caseIndex === null && node.parent !== null) {
    name.addEventListener("click", () => {
      if (node.expanded) collapse(node);
      else expand(model, node);
    });
  }
  return row;
}

function expand(model, node) {
  node.expanded = true;
  node.row.querySelector(".toggle").textContent = "▾";
  const rows = [];
  for (const child of node.children.values()) {
    if (!child.rendered) renderRow(model, child);
    child.row.hidden = false;
    rows.push(child.row);
  }
  // Fresh rows must be inserted; re-shown ones are already in place.
  if (rows.some((row) => !row.isConnected)) node.row.after(...rows);
}

function collapse(node) {
  node.expanded = false;
  if (node.row) node.row.querySelector(".toggle").textContent = "▸";
  for (const child of node.children.values()) {
    if (child.rendered) child.row.hidden = true;
    if (child.expanded) collapse(child);
  }
}

function renderTable(model) {
  const table = document.createElement("table");
  const head = document.createElement("tr");
  const caseHead = document.createElement("th");
  caseHead.className = "name";
  caseHead.textContent = "case";
  head.append(caseHead);
  for (const target of [...model.targets, "this browser"]) {
    const th = document.createElement("th");
    th.textContent = target;
    head.append(th);
  }
  table.createTHead().append(head);

  const body = table.createTBody();
  const totalRow = renderRow(model, model.root);
  totalRow.classList.add("total");
  totalRow.classList.remove("branch");
  totalRow.querySelector(".toggle").textContent = "";
  body.append(totalRow);
  for (const suite of model.root.children.values()) {
    body.append(renderRow(model, suite));
  }
  // The root always shows its children; its own toggle is disabled.
  model.root.expanded = true;
  model.root.rendered = true;

  el("main").replaceChildren(table);
}

/** Expand ancestors (root-most first) so `leaf`'s row is visible; each
 *  expansion renders the next level down. */
function expandPathTo(model, leaf) {
  const path = [];
  for (let node = leaf.parent; node && node.parent; node = node.parent) {
    path.unshift(node);
  }
  for (const node of path) {
    if (node.rendered && !node.expanded) expand(model, node);
  }
}

function autoExpandFailures(model) {
  let shown = 0;
  for (let i = 0; i < model.data.cases.length && shown < AUTO_EXPAND_LIMIT; i += 1) {
    const failing = model.targets.some((t) => model.data.outcomes[t]?.[i] === "f");
    if (failing) {
      expandPathTo(model, model.leaves[i]);
      shown += 1;
    }
  }
}

// --- the live run --------------------------------------------------------

function makeRun(model) {
  const status = el("status");
  const runButton = el("run");
  const downloadButton = el("download");
  const missing = model.data.targets[BROWSER_TARGET]?.["missing-features"];
  if (!missing) {
    runButton.disabled = true;
    status.textContent = `no ${BROWSER_TARGET} entry in the results data; cannot derive this browser's missing-features`;
    return;
  }
  if (typeof WebAssembly.Suspending !== "function") {
    runButton.disabled = true;
    status.replaceChildren("this browser does not support ");
    const link = document.createElement("a");
    link.href = JSPI_SUPPORT_URL;
    link.textContent = "WebAssembly JSPI";
    status.append(link, ", which the transpiled test suite needs");
    return;
  }

  // Per-corpus collected results, results-file-shaped for download.
  let collected;
  let received;
  let unexpected;
  let tagMismatches;
  let total;
  let pending;
  let flushTimer;

  const dirty = new Set();

  function reset() {
    collected = { shared: [], signing: [] };
    received = 0;
    unexpected = [];
    tagMismatches = 0;
    total = model.data.cases.length;
    pending = [];
    model.liveOutcomes.fill(null);
    model.liveDetails.fill("");
    for (const node of iterateNodes(model.root)) {
      const live = node.counts[model.liveColumn];
      live.p = 0;
      live.f = 0;
      live.s = 0;
      dirty.add(node);
    }
    flush();
  }

  function* iterateNodes(node) {
    yield node;
    for (const child of node.children.values()) yield* iterateNodes(child);
  }

  function apply(result) {
    (collected[result.corpus] ?? (collected[result.corpus] = [])).push({
      name: result.name,
      features: result.features,
      outcome: result.outcome,
      detail: result.detail,
    });
    received += 1;
    const index = model.indexByName.get(result.name);
    if (index === undefined || model.data.cases[index].corpus !== result.corpus) {
      unexpected.push(`${result.corpus}/${result.name}`);
      return;
    }
    const expectedTags = (model.data.cases[index].features ?? []).join(",");
    if (expectedTags !== result.features.join(",")) tagMismatches += 1;
    model.liveOutcomes[index] = CODE[result.outcome] ?? null;
    model.liveDetails[index] = result.detail;
    const code = CODE[result.outcome];
    if (code) {
      for (let node = model.leaves[index]; node; node = node.parent) {
        node.counts[model.liveColumn][code] += 1;
        dirty.add(node);
      }
    }
  }

  function flush() {
    for (const result of pending.splice(0)) apply(result);
    for (const node of dirty) updateLiveCell(model, node);
    dirty.clear();
  }

  function crossCheck() {
    const expected = new Map();
    for (const c of model.data.cases) {
      expected.set(c.corpus, (expected.get(c.corpus) ?? 0) + 1);
    }
    const problems = [];
    for (const [corpus, count] of expected) {
      const got = (collected[corpus] ?? []).length;
      if (got !== count) {
        problems.push(`${corpus}: ran ${got} of ${count} known cases`);
      }
    }
    if (unexpected.length > 0) {
      problems.push(
        `${unexpected.length} case(s) not in the static corpus (first: ${unexpected[0]})`,
      );
    }
    if (tagMismatches > 0) {
      problems.push(`${tagMismatches} case(s) with drifted feature tags`);
    }
    if (problems.length > 0) {
      warn(
        "this browser's run diverged from the static corpus (stale transpiled " +
          `guests? rerun \`just conformance-web\`):\n${problems.join("\n")}`,
      );
    }
  }

  function finish(error) {
    clearInterval(flushTimer);
    flush();
    runButton.disabled = false;
    runButton.textContent = "Run again";
    if (error) {
      status.textContent = "run failed — see the warning below";
      warn(`this browser's run failed:\n${error}`);
      return;
    }
    const live = model.root.counts[model.liveColumn];
    status.textContent =
      `done: ${live.p} passed, ${live.f} failed, ${live.s} skipped ` +
      `of ${received} run`;
    crossCheck();
    downloadButton.hidden = false;
  }

  function handle(message) {
    switch (message.kind) {
      case "start":
        // Several workers announce their shards; the flush timer's
        // progress counter is the real status line.
        status.textContent = "running…";
        break;
      case "result":
        pending.push(message);
        break;
      default:
        break;
    }
  }

  /**
   * Run the corpus across `count` parallel workers, each with its own
   * instances of the guests, running the `i % count` stripe of the cases.
   * Resolves to null when every worker finished, or to the first failure
   * (any worker failing aborts them all).
   */
  function runInWorkers(count) {
    return new Promise((resolve) => {
      const workers = [];
      let done = 0;
      let settled = false;
      const settle = (failure) => {
        if (settled) return;
        settled = true;
        for (const worker of workers) worker.terminate();
        resolve(failure);
      };
      for (let index = 0; index < count; index += 1) {
        let worker;
        try {
          worker = new Worker(new URL("./worker.mjs", import.meta.url), {
            type: "module",
          });
        } catch (err) {
          settle(String(err));
          return;
        }
        worker.onmessage = ({ data }) => {
          if (settled) return;
          if (data.kind === "error") {
            settle(data.error);
          } else if (data.kind === "done") {
            done += 1;
            if (done === count) settle(null);
          } else {
            handle(data);
          }
        };
        worker.onerror = (event) => {
          settle(String(event.message ?? "worker failed to start"));
        };
        worker.postMessage({ missing, shard: { index, count } });
        workers.push(worker);
      }
    });
  }

  async function start() {
    runButton.disabled = true;
    downloadButton.hidden = true;
    reset();
    status.textContent = "loading the test suite…";
    flushTimer = setInterval(() => {
      flush();
      if (received > 0) {
        status.textContent = `running… ${received} / ${total}`;
      }
    }, 100);

    // Parallel workers, one corpus stripe each; cases are self-contained
    // one-shots and each worker holds its own guest instances, so shards
    // cannot interfere. Fall back to a sequential main-thread run if the
    // worker path fails (e.g. no JSPI in workers) — partial worker results
    // are discarded by reset(). The run is fully async either way, so the
    // page stays responsive.
    const failure = await runInWorkers(
      Math.min(navigator.hardwareConcurrency || 2, 8),
    );
    if (failure === null) {
      finish();
      return;
    }
    console.warn(`worker run failed (${failure}); retrying on the main thread`);
    reset();
    try {
      await runAll(missing, handle);
      finish();
    } catch (err) {
      finish(String(err?.stack ?? err));
    }
  }

  function download() {
    for (const [corpus, results] of Object.entries(collected)) {
      if (results.length === 0) continue;
      // Workers interleave arbitrarily; restore corpus (lockfile) order.
      results.sort(
        (a, b) =>
          (model.indexByName.get(a.name) ?? 0) - (model.indexByName.get(b.name) ?? 0),
      );
      const report = {
        target: "this-browser",
        corpus,
        "missing-features": missing,
        results,
      };
      const blob = new Blob([`${JSON.stringify(report, null, 2)}\n`], {
        type: "application/json",
      });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = corpus === "shared" ? "this-browser.json" : `this-browser-${corpus}.json`;
      a.click();
      URL.revokeObjectURL(a.href);
    }
  }

  runButton.addEventListener("click", start);
  downloadButton.addEventListener("click", download);
}

// --- entry ---------------------------------------------------------------

async function main() {
  let data;
  try {
    const response = await fetch(DATA_URL);
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    data = await response.json();
  } catch (err) {
    el("run").disabled = true;
    el("main").textContent =
      `no results data at ${DATA_URL} (${err}) — serve this page with ` +
      "`just conformance-web`, which runs the conformance suite first";
    return;
  }
  const model = buildModel(data);
  renderTable(model);
  autoExpandFailures(model);
  makeRun(model);
}

main();
