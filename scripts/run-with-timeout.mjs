#!/usr/bin/env node
// Bound a command's runtime: run-with-timeout.mjs <seconds> -- <cmd> [args...]
//
// Exists because GNU `timeout` is Linux-only and the WebKit parity leg runs
// on macOS; Node is already a prerequisite of every caller, so this is the
// portable equivalent. Semantics follow `timeout <secs> <cmd>`: the child's
// exit status is forwarded, and on expiry the wrapper exits 124 after
// killing the child's whole process group (npm and Playwright spawn
// children, so killing only the direct child would leave the tree running).

import { spawn } from "node:child_process";
import { constants } from "node:os";

const argv = process.argv.slice(2);
const sep = argv.indexOf("--");
const seconds = Number(argv[0]);
const command = sep === -1 ? argv.slice(1) : argv.slice(sep + 1);
if (!Number.isFinite(seconds) || seconds <= 0 || command.length === 0) {
  console.error("usage: run-with-timeout.mjs <seconds> -- <command> [args...]");
  process.exit(125);
}

// `detached` puts the child in its own process group, so kill(-pid)
// reaches every descendant.
const child = spawn(command[0], command.slice(1), {
  stdio: "inherit",
  detached: true,
});

const killTree = (signal) => {
  try {
    process.kill(-child.pid, signal);
  } catch {
    // The group is already gone.
  }
};

let timedOut = false;
const timer = setTimeout(() => {
  timedOut = true;
  console.error(
    `run-with-timeout: '${command.join(" ")}' exceeded ${seconds}s; killing its process group`,
  );
  killTree("SIGTERM");
  // Grace period before the uncatchable kill, like `timeout -k`.
  setTimeout(() => killTree("SIGKILL"), 5000).unref();
}, seconds * 1000);

// The detached child is outside the terminal's foreground process group,
// so terminal signals must be forwarded to it.
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => killTree(signal));
}

child.on("error", (err) => {
  clearTimeout(timer);
  console.error(`run-with-timeout: ${err.message}`);
  process.exit(127);
});

child.on("exit", (code, signal) => {
  clearTimeout(timer);
  if (timedOut) process.exit(124);
  if (signal !== null) process.exit(128 + (constants.signals[signal] ?? 0));
  process.exit(code ?? 1);
});
