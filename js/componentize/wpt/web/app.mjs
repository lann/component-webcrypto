// The browser WPT parity page: runs the vendored WPT WebCryptoAPI suites
// twice in *this* browser — directly against its own `crypto.subtle` (the
// baseline leg) and through the componentized shim transpiled by jco
// against js/jco/webcrypto.js (the round-trip leg) — and renders the
// delta. It is the in-browser counterpart of `just wpt::parity` (see
// ../README.md, "The parity gate"): same group table (../groups.js), same
// record shape, same loss definition. Nothing here gates; the pinned loss
// ratchet belongs to the Node legs.
//
// Both legs run in a Web Worker (worker.mjs), streaming results back as
// they settle — the round trip's records arrive mid-run through the parity
// runner's `wpt:parity/reporter` import — with a sequential main-thread
// fallback over the same legs module (legs.mjs) if the worker path fails.
//
// Module paths resolve relative to this file, so the page works from any
// base path; the transpiled runner resolves its own relative imports the
// same way, so the serving tree must mirror the repository layout
// (scripts/serve-repo-root.mjs and the Pages site both do).

import { GROUPS } from "../groups.js";

const JSPI_SUPPORT_URL = "https://caniuse.com/wf-wasm-jspi";
// Cap on failing rows given expandable detail blocks in the run summary.
const FAILURE_DETAIL_LIMIT = 200;

const el = (id) => document.getElementById(id);

function warn(message) {
  const div = document.createElement("div");
  div.className = "warning";
  div.textContent = message;
  el("warnings").append(div);
}

// A leg failing somewhere the run's own try/catch cannot see (an event
// handler, a detached promise chain) must still leave a trace.
window.addEventListener("error", (event) => warn(`page error: ${event.message}`));
window.addEventListener("unhandledrejection", (event) =>
  warn(`unhandled rejection: ${String(event.reason?.stack ?? event.reason)}`),
);

// --- model -----------------------------------------------------------------

/**
 * One group per ../groups.js entry, rows keyed like the parity comparator
 * (test name, registration-order duplicates disambiguated with ` #n` —
 * both legs run the suites sequentially, so order is stable; the counters
 * in `seen` persist across streamed batches).
 */
function makeModel() {
  const groups = GROUPS.map(({ name, inSubset }) => ({
    name,
    inSubset,
    rows: new Map(),
    counts: null,
    row: null,
    cells: null,
    expanded: false,
    leafRows: [],
  }));
  return {
    groups,
    byName: new Map(groups.map((group) => [group.name, group])),
    unknownGroups: new Set(),
    seen: { baseline: new Map(), roundtrip: new Map() },
    baselineRecords: [],
    roundtripRecords: [],
    // idle -> streaming -> done; skipped when the round trip cannot run.
    roundtripState: "idle",
    totalCells: null,
  };
}

/**
 * Fold one leg's records (each carrying its group) into the model's rows;
 * returns the groups touched, for targeted refresh.
 * @param {{ group: string, name: string, status: string, message?: string }[]} records
 * @param {"baseline" | "roundtrip"} leg
 */
function addRecords(model, records, leg) {
  const seen = model.seen[leg];
  const touched = new Set();
  for (const record of records) {
    const target = model.byName.get(record.group);
    if (!target) {
      model.unknownGroups.add(record.group);
      continue;
    }
    touched.add(target);
    const base = `${record.group} :: ${record.name}`;
    const n = (seen.get(base) ?? 0) + 1;
    seen.set(base, n);
    const key = n === 1 ? record.name : `${record.name} #${n}`;
    let row = target.rows.get(key);
    if (!row) {
      row = { label: key, name: record.name, inSubset: null, baseline: null, roundtrip: null, category: null };
      target.rows.set(key, row);
    }
    row[leg] = { status: record.status, message: record.message };
  }
  return touched;
}

/**
 * (Re)classify one group's rows and counts. A *loss* is a baseline pass
 * the round trip fails or never registers; a *gain* is the reverse — not
 * a loss, but the shim diverging from the platform. Neither is knowable
 * mid-stream ("never registers" needs the end of the run), so both wait
 * for `roundtripState === "done"`.
 */
function classifyGroup(model, group) {
  const done = model.roundtripState === "done";
  const counts = { total: 0, in: 0, bPass: 0, rPass: 0, rSeen: 0, losses: 0, lossesIn: 0, gains: 0 };
  for (const row of group.rows.values()) {
    row.inSubset = group.inSubset(row.name);
    const b = row.baseline?.status === "PASS";
    const r = row.roundtrip?.status === "PASS";
    if (done) {
      row.category = b && r ? "pass" : b ? "loss" : r ? "gain" : "fail";
    } else {
      row.category = b ? "pass" : "fail";
    }
    counts.total += 1;
    if (row.inSubset) counts.in += 1;
    if (b) counts.bPass += 1;
    if (r) counts.rPass += 1;
    if (row.roundtrip) counts.rSeen += 1;
    if (done) {
      if (b && !r) {
        counts.losses += 1;
        if (row.inSubset) counts.lossesIn += 1;
      }
      if (!b && r) counts.gains += 1;
    }
  }
  group.counts = counts;
}

/** Sum every group's counts. */
function totalCounts(model) {
  const total = { total: 0, in: 0, bPass: 0, rPass: 0, rSeen: 0, losses: 0, lossesIn: 0, gains: 0 };
  for (const group of model.groups) {
    if (!group.counts) continue;
    for (const key of Object.keys(total)) total[key] += group.counts[key];
  }
  return total;
}

// --- rendering -----------------------------------------------------------

/** Whether a leaf row renders under the current filter: everything, or —
 *  the default — only the differences (losses and gains; the baseline's
 *  own failures until the round trip finished). */
function rowVisible(model, row, showAll) {
  if (showAll) return true;
  if (model.roundtripState !== "done") return row.category === "fail";
  return row.category === "loss" || row.category === "gain";
}

function legCell(cell, leg, ran) {
  if (leg === null || leg === undefined) {
    cell.textContent = ran ? "—" : "";
    cell.className = "none";
    return;
  }
  if (leg.status === "PASS") {
    cell.textContent = "✓";
    cell.className = "pass";
  } else {
    cell.textContent = "✗";
    cell.className = "fail";
    if (leg.message) cell.title = leg.message;
  }
}

/** Fill a group's (or the total row's) four count cells. */
function countCells(model, cells, counts) {
  const [subset, baseline, roundtrip, delta] = cells;
  if (counts.total === 0) {
    for (const cell of cells) {
      cell.textContent = "";
      cell.className = "";
    }
    return;
  }
  subset.textContent = `${counts.in}/${counts.total} in`;
  subset.className = "none";
  baseline.textContent = `${counts.bPass}/${counts.total}`;
  baseline.className = counts.bPass === counts.total ? "pass" : "";
  switch (model.roundtripState) {
    case "streaming":
      roundtrip.textContent = counts.rSeen > 0 ? `${counts.rPass}/${counts.rSeen}…` : "…";
      roundtrip.className = "none";
      delta.textContent = "";
      delta.className = "";
      return;
    case "done": {
      roundtrip.textContent = `${counts.rPass}/${counts.total}`;
      roundtrip.className = counts.rPass === counts.total ? "pass" : "";
      let text = "";
      if (counts.losses > 0) {
        text = `✗${counts.losses}`;
        if (counts.lossesIn > 0) text += ` (${counts.lossesIn} in)`;
      }
      if (counts.gains > 0) text += `${text ? " " : ""}+${counts.gains}`;
      delta.textContent = text || "=";
      delta.className = counts.lossesIn > 0 ? "fail" : counts.losses > 0 ? "skip" : "pass";
      return;
    }
    default:
      roundtrip.textContent = "—";
      roundtrip.className = "none";
      delta.textContent = "";
      delta.className = "";
  }
}

function renderLeafRows(model, group, showAll) {
  for (const row of group.leafRows) row.remove();
  group.leafRows = [];
  if (!group.expanded) return;
  const ranRoundtrip = model.roundtripState !== "idle" && model.roundtripState !== "skipped";
  const fragment = document.createDocumentFragment();
  let hidden = 0;
  for (const row of group.rows.values()) {
    if (!rowVisible(model, row, showAll)) {
      hidden += 1;
      continue;
    }
    const tr = document.createElement("tr");
    tr.className = "leaf";
    const name = document.createElement("td");
    name.className = "name";
    name.style.paddingLeft = "1.7em";
    name.textContent = row.label;
    tr.append(name);
    const subset = document.createElement("td");
    subset.textContent = row.inSubset ? "in" : "out";
    subset.className = row.inSubset ? "" : "none";
    tr.append(subset);
    const baseline = document.createElement("td");
    legCell(baseline, row.baseline, true);
    tr.append(baseline);
    const roundtrip = document.createElement("td");
    legCell(roundtrip, row.roundtrip, ranRoundtrip);
    tr.append(roundtrip);
    const delta = document.createElement("td");
    if (row.category === "loss") {
      delta.textContent = "loss";
      delta.className = row.inSubset ? "fail" : "skip";
    } else if (row.category === "gain") {
      delta.textContent = "gain";
      delta.className = "skip";
    } else {
      delta.textContent = "";
    }
    tr.append(delta);
    fragment.append(tr);
    group.leafRows.push(tr);
  }
  if (hidden > 0 && !showAll) {
    const tr = document.createElement("tr");
    tr.className = "leaf";
    const note = document.createElement("td");
    note.className = "name none";
    note.colSpan = 5;
    note.style.paddingLeft = "1.7em";
    note.textContent = `${hidden} test(s) hidden — "show all tests" reveals them`;
    tr.append(note);
    fragment.append(tr);
    group.leafRows.push(tr);
  }
  group.row.after(...group.leafRows);
}

function renderTable(model) {
  const table = document.createElement("table");
  const head = document.createElement("tr");
  const caseHead = document.createElement("th");
  caseHead.className = "name";
  caseHead.textContent = "group / test";
  head.append(caseHead);
  for (const label of ["subset", "baseline", "round trip", "delta"]) {
    const th = document.createElement("th");
    th.textContent = label;
    head.append(th);
  }
  table.createTHead().append(head);

  const body = table.createTBody();
  const totalRow = document.createElement("tr");
  totalRow.className = "total";
  const totalName = document.createElement("td");
  totalName.className = "name";
  totalName.textContent = "all groups";
  totalRow.append(totalName);
  model.totalCells = ["subset", "baseline", "roundtrip", "delta"].map(() => {
    const cell = document.createElement("td");
    totalRow.append(cell);
    return cell;
  });
  body.append(totalRow);

  for (const group of model.groups) {
    const tr = document.createElement("tr");
    tr.className = "branch";
    const name = document.createElement("td");
    name.className = "name";
    const toggle = document.createElement("span");
    toggle.className = "toggle";
    toggle.textContent = "▸";
    name.append(toggle, group.name);
    tr.append(name);
    group.cells = ["subset", "baseline", "roundtrip", "delta"].map(() => {
      const cell = document.createElement("td");
      tr.append(cell);
      return cell;
    });
    group.row = tr;
    name.addEventListener("click", () => {
      group.expanded = !group.expanded;
      toggle.textContent = group.expanded ? "▾" : "▸";
      renderLeafRows(model, group, el("show-all").checked);
    });
    body.append(tr);
  }
  el("main").replaceChildren(table);
}

function refreshGroup(model, group) {
  classifyGroup(model, group);
  countCells(model, group.cells, group.counts);
  if (group.expanded) renderLeafRows(model, group, el("show-all").checked);
}

function refreshTotals(model) {
  countCells(model, model.totalCells, totalCounts(model));
}

// --- the run summary -------------------------------------------------------

/** Render the completed run's summary: headline counts, then the in-subset
 *  losses (the tests the shim claims to serve and the stack loses on this
 *  browser), one expandable detail per loss. */
function renderSummary(model) {
  const section = el("summary");
  const counts = totalCounts(model);
  const fragment = document.createDocumentFragment();

  const heading = document.createElement("h2");
  heading.textContent = "This browser's parity";
  fragment.append(heading);
  const line = document.createElement("p");
  line.textContent =
    model.roundtripState === "done"
      ? `Baseline: ${counts.bPass}/${counts.total} passed. Round trip: ${counts.rPass} passed; ` +
        `${counts.losses} losses (${counts.lossesIn} in-subset), ${counts.gains} divergent passes.`
      : `Baseline: ${counts.bPass}/${counts.total} passed. The round trip did not run.`;
  fragment.append(line);

  if (model.roundtripState === "done") {
    const losses = [];
    for (const group of model.groups) {
      for (const row of group.rows.values()) {
        if (row.category === "loss" && row.inSubset) losses.push([group.name, row]);
      }
    }
    if (losses.length === 0) {
      const none = document.createElement("p");
      none.className = "note";
      none.textContent = "No in-subset losses: every in-subset test this browser passes survives the stack.";
      fragment.append(none);
    } else {
      const intro = document.createElement("p");
      intro.textContent = "In-subset losses:";
      fragment.append(intro);
      losses.slice(0, FAILURE_DETAIL_LIMIT).forEach(([groupName, row]) => {
        const details = document.createElement("details");
        const summary = document.createElement("summary");
        summary.textContent = `${groupName} :: ${row.label}`;
        details.append(summary);
        const pre = document.createElement("pre");
        pre.textContent = row.roundtrip
          ? row.roundtrip.message || row.roundtrip.status
          : "never registered in the round trip";
        details.append(pre);
        fragment.append(details);
      });
      if (losses.length > FAILURE_DETAIL_LIMIT) {
        const note = document.createElement("p");
        note.className = "note";
        note.textContent = `Details shown for the first ${FAILURE_DETAIL_LIMIT} of ${losses.length} in-subset losses.`;
        fragment.append(note);
      }
    }
  }

  section.replaceChildren(fragment);
  section.hidden = false;
}

// --- the run ---------------------------------------------------------------

/**
 * Run both legs in a Web Worker, forwarding every message but the terminal
 * `done`/`error` to `onMessage`. Resolves to null on completion or to the
 * failure — callers discard partial results and fall back to the
 * main-thread path.
 * @param {boolean} runRoundtrip
 * @param {(message: object) => void} onMessage
 * @returns {Promise<string | null>}
 */
function runInWorker(runRoundtrip, onMessage) {
  return new Promise((resolve) => {
    let worker;
    let settled = false;
    const settle = (failure) => {
      if (settled) return;
      settled = true;
      worker?.terminate();
      resolve(failure);
    };
    try {
      worker = new Worker(new URL("./worker.mjs", import.meta.url), { type: "module" });
    } catch (err) {
      settle(String(err));
      return;
    }
    worker.onmessage = ({ data }) => {
      if (settled) return;
      if (data.kind === "error") settle(data.error);
      else if (data.kind === "done") settle(null);
      else onMessage(data);
    };
    worker.onerror = (event) => settle(String(event.message ?? "worker failed to start"));
    worker.postMessage({ runRoundtrip });
  });
}

/** The main-thread fallback: the same legs, run inline. */
async function runInline(runRoundtrip, onMessage) {
  const { runBaselineLeg, runRoundtripLeg } = await import("./legs.mjs");
  await runBaselineLeg((group, results) => onMessage({ kind: "baseline-group", group, results }));
  if (runRoundtrip) {
    onMessage({ kind: "roundtrip-start" });
    const count = await runRoundtripLeg((records) => onMessage({ kind: "roundtrip-records", records }));
    onMessage({ kind: "roundtrip-done", count });
  }
}

function main() {
  const status = el("status");
  const runButton = el("run");
  const downloadButton = el("download");
  const showAll = el("show-all");
  const jspi = typeof WebAssembly.Suspending === "function";

  let model = makeModel();
  renderTable(model);

  if (!jspi) {
    status.replaceChildren("the round trip needs ");
    const link = document.createElement("a");
    link.href = JSPI_SUPPORT_URL;
    link.textContent = "WebAssembly JSPI";
    status.append(link, ", which this browser lacks; the run covers the baseline only");
  }

  showAll.addEventListener("change", () => {
    for (const group of model.groups) {
      if (group.expanded) renderLeafRows(model, group, showAll.checked);
    }
  });

  let running = false;

  async function start() {
    runButton.disabled = true;
    downloadButton.hidden = true;
    el("warnings").replaceChildren();
    el("summary").hidden = true;
    model = makeModel();
    if (!jspi) model.roundtripState = "skipped";
    renderTable(model);
    running = true;

    const started = Date.now();
    let phase = "baseline";
    let groupsDone = 0;
    let received = 0;
    const elapsed = () => `${Math.round((Date.now() - started) / 1000)}s`;
    const ticker = setInterval(() => {
      if (!running) return;
      status.textContent =
        phase === "baseline"
          ? `baseline: ${groupsDone}/${GROUPS.length} groups — ${elapsed()}`
          : `round trip: ${received.toLocaleString()} results — ${elapsed()}`;
    }, 500);

    const handle = (message) => {
      switch (message.kind) {
        case "baseline-group": {
          groupsDone += 1;
          for (const { name, status: s, message: m } of message.results) {
            model.baselineRecords.push(
              m === undefined
                ? { group: message.group, name, status: s }
                : { group: message.group, name, status: s, message: m },
            );
          }
          const touched = addRecords(
            model,
            model.baselineRecords.slice(model.baselineRecords.length - message.results.length),
            "baseline",
          );
          for (const group of touched) refreshGroup(model, group);
          refreshTotals(model);
          break;
        }
        case "roundtrip-start":
          phase = "roundtrip";
          model.roundtripState = "streaming";
          break;
        case "roundtrip-records": {
          received += message.records.length;
          model.roundtripRecords.push(...message.records);
          const touched = addRecords(model, message.records, "roundtrip");
          for (const group of touched) refreshGroup(model, group);
          refreshTotals(model);
          break;
        }
        case "roundtrip-done":
          model.roundtripState = "done";
          break;
        default:
          break;
      }
    };

    let error = null;
    const failure = await runInWorker(jspi, handle);
    if (failure !== null) {
      console.warn(`worker run failed (${failure}); retrying on the main thread`);
      warn(`the worker run failed (retried on the main thread):\n${failure}`);
      model = makeModel();
      if (!jspi) model.roundtripState = "skipped";
      renderTable(model);
      phase = "baseline";
      groupsDone = 0;
      received = 0;
      try {
        await runInline(jspi, handle);
      } catch (err) {
        error = String(err?.stack ?? err);
      }
    }

    running = false;
    clearInterval(ticker);
    if (model.roundtripState === "streaming") {
      // The round trip started but never finished; without its full record
      // set, losses are not computable.
      model.roundtripState = "idle";
      if (error === null) error = "the round trip ended without completing";
    }
    for (const group of model.groups) refreshGroup(model, group);
    refreshTotals(model);
    if (model.unknownGroups.size > 0) {
      warn(
        `record(s) for group(s) not in ../groups.js (stale artifacts? rebuild with \`just wpt-web-artifacts\`): ` +
          [...model.unknownGroups].join(", "),
      );
    }

    const counts = totalCounts(model);
    if (error !== null) {
      status.textContent = "run failed — see the warning below";
      warn(`this run failed:\n${error}`);
    } else {
      status.textContent =
        model.roundtripState === "done"
          ? `done in ${elapsed()}: baseline ${counts.bPass}/${counts.total}, round trip ${counts.rPass}, ` +
            `${counts.losses} losses (${counts.lossesIn} in-subset)`
          : `done in ${elapsed()}: baseline ${counts.bPass}/${counts.total} (round trip not run)`;
      renderSummary(model);
      downloadButton.hidden = false;
    }
    runButton.disabled = false;
    runButton.textContent = "Run again";
  }

  function download() {
    const files = [["this-browser-baseline.json", model.baselineRecords]];
    if (model.roundtripState === "done") files.push(["this-browser-roundtrip.json", model.roundtripRecords]);
    for (const [name, records] of files) {
      const blob = new Blob([`${JSON.stringify(records)}\n`], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = name;
      a.click();
      URL.revokeObjectURL(a.href);
    }
  }

  runButton.addEventListener("click", start);
  downloadButton.addEventListener("click", download);
}

main();
