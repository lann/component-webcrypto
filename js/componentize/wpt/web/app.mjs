// The browser WPT parity page: runs the vendored WPT WebCryptoAPI suites
// twice in *this* browser — directly against its own `crypto.subtle` (the
// baseline leg) and through the componentized shim transpiled by jco
// against js/jco/webcrypto.js (the round-trip leg) — and renders the
// delta. It is the in-browser counterpart of `just wpt-parity` (see
// ../README.md, "The parity gate"): same group table (../groups.js), same
// record shape, same loss definition. Nothing here gates; the pinned loss
// ratchet belongs to the Node legs.
//
// Both legs run on the main thread. The round trip's generated module
// resolves its wasi imports through the document's import map (see
// index.html), which module workers do not read; the harness awaits every
// test, so the page stays responsive without them.
//
// Module paths resolve relative to this file, so the page works from any
// base path; the transpiled runner resolves its own relative import of
// js/jco/webcrypto.js the same way, so the serving tree must mirror the
// repository layout (like the conformance viewer — see
// conformance/web/harness.mjs).

import { GROUPS } from "../groups.js";
import { drain, takeResults } from "../harness.js";

const JSPI_SUPPORT_URL = "https://caniuse.com/wf-wasm-jspi";
const RUNNER_URL = new URL("../parity/generated/parity-runner.js", import.meta.url).href;
// Cap on failing rows given expandable detail blocks in the run summary.
const FAILURE_DETAIL_LIMIT = 200;

const el = (id) => document.getElementById(id);

function warn(message) {
  const div = document.createElement("div");
  div.className = "warning";
  div.textContent = message;
  el("warnings").append(div);
}

// --- the legs ------------------------------------------------------------

/**
 * The baseline leg: each group's suite module imported beside ../build/
 * and run against this browser's own crypto, reporting per group. The
 * explicit macrotask lets the table paint between groups (the harness's
 * own awaits may settle as microtasks for pure-JS tests).
 * @param {(group: string, results: { name: string, status: string, message?: string }[]) => void} onGroup
 */
async function runBaseline(onGroup) {
  for (const { name: group, module, start } of GROUPS) {
    await new Promise((resolve) => setTimeout(resolve));
    start(await import(new URL(`../build/${module}`, import.meta.url).href));
    await drain();
    onGroup(group, takeResults());
  }
}

/**
 * Unwrap jco's representation of a WIT `result<string, string>` returned
 * by an exported function — a convention, not documented API (validated
 * against jco-transpile 0.5.x; see examples/jco-demo/src/run.mjs, where
 * the same convention is anchored).
 * @param {() => Promise<unknown>} call
 */
async function unwrapResult(call) {
  let value;
  try {
    value = await call();
  } catch (err) {
    throw new Error(`returned err: ${err?.payload ?? err?.val ?? err}`);
  }
  if (typeof value === "object" && value !== null && "tag" in value) {
    if (value.tag !== "ok") {
      throw new Error(`returned err: ${value.val}`);
    }
    value = value.val;
  }
  return value;
}

/**
 * The round-trip leg: one call into the transpiled parity runner, whose
 * records come back as the `WPT-PARITY-RESULTS` marker plus JSON (see
 * ../parity-runner.js). Imported on demand so a browser without JSPI never
 * fetches the component.
 * @returns {Promise<{ group: string, name: string, status: string, message?: string }[]>}
 */
async function runRoundtrip() {
  const { demo } = await import(RUNNER_URL);
  const output = await unwrapResult(() => demo.run());
  const marker = "WPT-PARITY-RESULTS\n";
  if (typeof output !== "string" || !output.startsWith(marker)) {
    throw new Error(`parity runner returned an unexpected shape: ${String(output).slice(0, 200)}`);
  }
  return JSON.parse(output.slice(marker.length));
}

// --- model -----------------------------------------------------------------

/**
 * One group per ../groups.js entry, rows keyed like the parity comparator
 * (test name, registration-order duplicates disambiguated with ` #n` —
 * both legs run the suites sequentially, so order is stable).
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
    baselineRecords: [],
    roundtripRecords: [],
    ranRoundtrip: false,
  };
}

/** Fold one leg's records for one group into its rows. */
function addLeg(model, group, records, leg) {
  const target = model.byName.get(group);
  if (!target) {
    model.unknownGroups.add(group);
    return;
  }
  const seen = new Map();
  for (const record of records) {
    const n = (seen.get(record.name) ?? 0) + 1;
    seen.set(record.name, n);
    const key = n === 1 ? record.name : `${record.name} #${n}`;
    let row = target.rows.get(key);
    if (!row) {
      row = { label: key, name: record.name, inSubset: null, baseline: null, roundtrip: null, category: null };
      target.rows.set(key, row);
    }
    row[leg] = { status: record.status, message: record.message };
  }
}

/**
 * (Re)classify one group's rows and counts. A *loss* is a baseline pass
 * the round trip fails or never registers; a *gain* is the reverse — not
 * a loss, but the shim diverging from the platform. Neither is computed
 * until the round trip ran.
 */
function classifyGroup(model, group) {
  const counts = { total: 0, in: 0, bPass: 0, rPass: 0, losses: 0, lossesIn: 0, gains: 0 };
  for (const row of group.rows.values()) {
    row.inSubset = group.inSubset(row.name);
    const b = row.baseline?.status === "PASS";
    const r = row.roundtrip?.status === "PASS";
    if (model.ranRoundtrip) {
      row.category = b && r ? "pass" : b ? "loss" : r ? "gain" : "fail";
    } else {
      row.category = b ? "pass" : "fail";
    }
    counts.total += 1;
    if (row.inSubset) counts.in += 1;
    if (b) counts.bPass += 1;
    if (r) counts.rPass += 1;
    if (model.ranRoundtrip) {
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
  const total = { total: 0, in: 0, bPass: 0, rPass: 0, losses: 0, lossesIn: 0, gains: 0 };
  for (const group of model.groups) {
    if (!group.counts) continue;
    for (const key of Object.keys(total)) total[key] += group.counts[key];
  }
  return total;
}

// --- rendering -----------------------------------------------------------

/** Whether a leaf row renders under the current filter: everything, or —
 *  the default — only the differences (losses and gains; the baseline's
 *  own failures when the round trip did not run). */
function rowVisible(model, row, showAll) {
  if (showAll) return true;
  if (!model.ranRoundtrip) return row.category === "fail";
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

function groupCells(model, group) {
  const { counts } = group;
  const [subset, baseline, roundtrip, delta] = group.cells;
  subset.textContent = counts.total === 0 ? "" : `${counts.in}/${counts.total} in`;
  subset.className = "none";
  baseline.textContent = counts.total === 0 ? "" : `${counts.bPass}/${counts.total}`;
  baseline.className = counts.bPass === counts.total ? "pass" : "";
  if (!model.ranRoundtrip) {
    roundtrip.textContent = counts.total === 0 ? "" : "—";
    roundtrip.className = "none";
    delta.textContent = "";
    delta.className = "";
    return;
  }
  roundtrip.textContent = `${counts.rPass}/${counts.total}`;
  roundtrip.className = counts.rPass === counts.total ? "pass" : "";
  let text = "";
  if (counts.losses > 0) {
    text = `✗${counts.losses}`;
    if (counts.lossesIn > 0) text += ` (${counts.lossesIn} in)`;
  }
  if (counts.gains > 0) text += `${text ? " " : ""}+${counts.gains}`;
  delta.textContent = text;
  delta.className = counts.lossesIn > 0 ? "fail" : counts.losses > 0 ? "skip" : "pass";
  if (counts.losses === 0 && counts.gains === 0 && counts.total > 0) delta.textContent = "=";
}

function renderLeafRows(model, group, showAll) {
  for (const row of group.leafRows) row.remove();
  group.leafRows = [];
  if (!group.expanded) return;
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
    legCell(roundtrip, row.roundtrip, model.ranRoundtrip);
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
  groupCells(model, group);
  if (group.expanded) renderLeafRows(model, group, el("show-all").checked);
}

function refreshTotals(model) {
  const counts = totalCounts(model);
  const [subset, baseline, roundtrip, delta] = model.totalCells;
  subset.textContent = counts.total === 0 ? "" : `${counts.in}/${counts.total} in`;
  baseline.textContent = counts.total === 0 ? "" : `${counts.bPass}/${counts.total}`;
  baseline.className = "";
  if (!model.ranRoundtrip) {
    roundtrip.textContent = "";
    delta.textContent = "";
    return;
  }
  roundtrip.textContent = `${counts.rPass}/${counts.total}`;
  let text = "";
  if (counts.losses > 0) {
    text = `✗${counts.losses}`;
    if (counts.lossesIn > 0) text += ` (${counts.lossesIn} in)`;
  }
  if (counts.gains > 0) text += `${text ? " " : ""}+${counts.gains}`;
  delta.textContent = text || "=";
  delta.className = counts.lossesIn > 0 ? "fail" : counts.losses > 0 ? "skip" : "pass";
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
  line.textContent = model.ranRoundtrip
    ? `Baseline: ${counts.bPass}/${counts.total} passed. Round trip: ${counts.rPass} passed; ` +
      `${counts.losses} losses (${counts.lossesIn} in-subset), ${counts.gains} divergent passes.`
    : `Baseline: ${counts.bPass}/${counts.total} passed. The round trip did not run.`;
  fragment.append(line);

  if (model.ranRoundtrip) {
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

  async function start() {
    runButton.disabled = true;
    downloadButton.hidden = true;
    el("warnings").replaceChildren();
    el("summary").hidden = true;
    model = makeModel();
    renderTable(model);

    try {
      let done = 0;
      await runBaseline((group, results) => {
        done += 1;
        status.textContent = `baseline: ${done}/${GROUPS.length} groups run`;
        for (const { name, status: s, message } of results) {
          model.baselineRecords.push(
            message === undefined ? { group, name, status: s } : { group, name, status: s, message },
          );
        }
        addLeg(model, group, results, "baseline");
        const target = model.byName.get(group);
        if (target) {
          classifyGroup(model, target);
          refreshGroup(model, target);
        }
        refreshTotals(model);
      });
    } catch (err) {
      status.textContent = "the baseline failed";
      warn(`the baseline leg failed:\n${String(err?.stack ?? err)}`);
      runButton.disabled = false;
      return;
    }

    if (jspi) {
      status.textContent = "round trip: running (one call into the transpiled component)…";
      try {
        const records = await runRoundtrip();
        model.roundtripRecords = records;
        model.ranRoundtrip = true;
        const byGroup = new Map();
        for (const record of records) {
          let list = byGroup.get(record.group);
          if (!list) byGroup.set(record.group, (list = []));
          list.push(record);
        }
        for (const [group, list] of byGroup) addLeg(model, group, list, "roundtrip");
      } catch (err) {
        warn(`the round-trip leg failed; showing the baseline only:\n${String(err?.stack ?? err)}`);
      }
    }

    for (const group of model.groups) {
      classifyGroup(model, group);
      refreshGroup(model, group);
    }
    refreshTotals(model);
    if (model.unknownGroups.size > 0) {
      warn(
        `record(s) for group(s) not in ../groups.js (stale artifacts? rebuild with \`just wpt-web-artifacts\`): ` +
          [...model.unknownGroups].join(", "),
      );
    }

    const counts = totalCounts(model);
    status.textContent = model.ranRoundtrip
      ? `done: baseline ${counts.bPass}/${counts.total}, round trip ${counts.rPass}, ` +
        `${counts.losses} losses (${counts.lossesIn} in-subset)`
      : `done: baseline ${counts.bPass}/${counts.total} (round trip not run)`;
    renderSummary(model);
    downloadButton.hidden = false;
    runButton.disabled = false;
    runButton.textContent = "Run again";
  }

  function download() {
    const files = [["this-browser-baseline.json", model.baselineRecords]];
    if (model.ranRoundtrip) files.push(["this-browser-roundtrip.json", model.roundtripRecords]);
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
