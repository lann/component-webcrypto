// Tests for the input-buffering admission subsystem.
//
// #76 recorded that none of this was exercised by any gate: the conformance
// adapter runs cases strictly sequentially, so no test here had ever seen two
// operations in flight at once. These run the host directly — no component, no
// jco — because the subsystem is reached through the same class methods a
// transpiled component calls.
//
// The deadlock test is a guard, not a demonstration: it pins the precondition
// so that the fix for the release-timing defect (#76.2) cannot land without
// someone reading why the two interact.

import assert from "node:assert/strict";
import { after, beforeEach, test } from "node:test";

import { aesGcm, configure } from "../webcrypto.js";

/** Restore the shipped defaults, whatever a test set. */
const resetLimits = () =>
  configure({ perCallBufferLimit: undefined, totalBufferLimit: undefined });

beforeEach(resetLimits);
after(resetLimits);

const streamOf = (bytes) =>
  new ReadableStream({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });

/** A stream whose bytes arrive only when `feed()` is called. */
function heldStream() {
  let controller;
  const stream = new ReadableStream({
    start(c) {
      controller = c;
    },
  });
  return {
    stream,
    feed(bytes = new Uint8Array(64)) {
      controller.enqueue(bytes);
      controller.close();
    },
  };
}

/** Resolves to `"pending"` if `promise` has not settled within `ms`. */
const settledWithin = (promise, ms) =>
  Promise.race([
    promise.then(
      () => "resolved",
      () => "rejected",
    ),
    new Promise((resolve) => setTimeout(() => resolve("pending"), ms)),
  ]);

const drain = async (stream) => {
  const reader = stream.getReader();
  for (;;) {
    const { done } = await reader.read();
    if (done) return;
  }
};

const key = () => aesGcm.generateKey("aes256", false);
const NONCE = new Uint8Array(12);
const NO_AAD = new Uint8Array(0);

test("concurrent operations within the pool all complete", async () => {
  configure({ perCallBufferLimit: 1024, totalBufferLimit: 4096 });
  const aead = await key();
  const sealed = await Promise.all(
    Array.from({ length: 4 }, () => aead.seal(NONCE, NO_AAD, streamOf(new Uint8Array(64)))),
  );
  assert.equal(sealed.length, 4);
  await Promise.all(sealed.map(drain));
});

test("more operations than fit the pool still complete, one after another", async () => {
  configure({ perCallBufferLimit: 1024, totalBufferLimit: 4096 });
  const aead = await key();
  const sealed = await Promise.all(
    Array.from({ length: 32 }, () => aead.seal(NONCE, NO_AAD, streamOf(new Uint8Array(64)))),
  );
  assert.equal(sealed.length, 32);
  await Promise.all(sealed.map(drain));
});

test("an input past the per-call limit is drained and fails recoverably", async () => {
  configure({ perCallBufferLimit: 64, totalBufferLimit: 4096 });
  const aead = await key();
  await assert.rejects(
    () => aead.seal(NONCE, NO_AAD, streamOf(new Uint8Array(4096))),
    (err) => err.tag === "other",
  );
  // The pool is not leaked by the failure: a later operation is still admitted.
  configure({ perCallBufferLimit: 1024 });
  const sealed = await aead.seal(NONCE, NO_AAD, streamOf(new Uint8Array(64)));
  await drain(sealed);
});

test("withholding an admitted operation's input stalls a queued one", async () => {
  // The precondition for the deadlock, pinned. Four operations fit; the fifth
  // waits. Feeding only the fifth cannot release it, because the four ahead of
  // it hold the pool until their own inputs arrive.
  //
  // This is the caller obligation the WIT states as the making-progress note:
  // do not withhold one in-flight operation's input while awaiting another.
  configure({ perCallBufferLimit: 1024, totalBufferLimit: 4096 });
  const aead = await key();
  const held = Array.from({ length: 5 }, heldStream);
  const ops = held.map((h) => aead.seal(NONCE, NO_AAD, h.stream));
  const queued = ops[4];
  // Keep the rejection from going unhandled while we deliberately stall it.
  queued.catch(() => {});

  held[4].feed();
  assert.equal(await settledWithin(queued, 100), "pending");

  held.slice(0, 4).forEach((h) => h.feed());
  const sealed = await Promise.all(ops);
  await Promise.all(sealed.map(drain));
});

test("configure updates only the limits it is given", async () => {
  const aead = await key();
  configure({ perCallBufferLimit: 4096, totalBufferLimit: 16384 });

  // Updating the pool alone must leave the per-call limit alone. Clobbering
  // it would derive a per-call limit of a quarter of the new pool — 512 — and
  // reject this 1024-byte input.
  configure({ totalBufferLimit: 2048 });
  const sealed = await aead.seal(NONCE, NO_AAD, streamOf(new Uint8Array(1024)));
  await drain(sealed);

  // And the converse: updating the per-call limit alone leaves the pool.
  configure({ perCallBufferLimit: 512 });
  await assert.rejects(
    () => aead.seal(NONCE, NO_AAD, streamOf(new Uint8Array(1024))),
    (err) => err.tag === "other",
    "the per-call limit just set must be in force",
  );
});

test("a raised total admits a waiter queued against the old one", async () => {
  // The ceiling is read at admission time rather than snapshotted per waiter,
  // so a `configure` between queueing and admission governs the whole queue.
  // A snapshotting queue judges the waiter against the total in force when it
  // arrived, leaving it stuck behind an operation that the raised pool has
  // room to run alongside.
  configure({ perCallBufferLimit: 1024, totalBufferLimit: 1024 });
  const aead = await key();
  const first = heldStream();
  const second = heldStream();
  const ops = [
    aead.seal(NONCE, NO_AAD, first.stream),
    aead.seal(NONCE, NO_AAD, second.stream),
  ];
  ops.forEach((op) => op.catch(() => {}));

  second.feed();
  assert.equal(await settledWithin(ops[1], 50), "pending", "the pool holds one operation");

  // Room for both now. The queued operation must run without waiting for the
  // admitted one, whose input is still being withheld.
  configure({ totalBufferLimit: 4096 });
  assert.equal(
    await settledWithin(ops[1], 100),
    "resolved",
    "the waiter must be judged against the pool in force, not the one it arrived under",
  );

  first.feed();
  const sealed = await Promise.all(ops);
  await Promise.all(sealed.map(drain));
});
