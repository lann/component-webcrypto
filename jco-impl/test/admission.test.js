// Tests for the input-buffering admission subsystem.
//
// #76 recorded that none of this was exercised by any gate: the conformance
// adapter runs cases strictly sequentially, so no test here had ever seen two
// operations in flight at once. These run the host directly — no component, no
// jco — because the subsystem is reached through the same class methods a
// transpiled component calls.
//
// Every test that runs several operations drives them the way the package's
// making-progress note requires: each operation's output is drained by the
// task that awaited it. The two tests that deliberately do otherwise are
// guards, and say so.

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

/**
 * One operation, driven as the making-progress note requires: the output is
 * drained by the same task that awaited the operation, so the capacity it
 * holds is freed without waiting on any other operation.
 */
const sealAndDrain = (aead, stream) => aead.seal(NONCE, NO_AAD, stream).then(drain);

test("concurrent operations within the pool all complete", async () => {
  configure({ perCallBufferLimit: 1024, totalBufferLimit: 4096 });
  const aead = await key();
  await Promise.all(
    Array.from({ length: 4 }, () => sealAndDrain(aead, streamOf(new Uint8Array(64)))),
  );
});

test("more operations than fit the pool still complete, one after another", async () => {
  configure({ perCallBufferLimit: 1024, totalBufferLimit: 4096 });
  const aead = await key();
  await Promise.all(
    Array.from({ length: 32 }, () => sealAndDrain(aead, streamOf(new Uint8Array(64)))),
  );
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
  await sealAndDrain(aead, streamOf(new Uint8Array(64)));
});

test("an output holds its capacity until it is read", async () => {
  // The pool covers what the implementation retains, and an unconsumed output
  // is retained. Two fit; a third waits for one of them to be *drained*, not
  // merely to have returned.
  configure({ perCallBufferLimit: 1024, totalBufferLimit: 2048 });
  const aead = await key();
  const first = await aead.seal(NONCE, NO_AAD, streamOf(new Uint8Array(64)));
  const second = await aead.seal(NONCE, NO_AAD, streamOf(new Uint8Array(64)));

  const third = aead.seal(NONCE, NO_AAD, streamOf(new Uint8Array(64)));
  third.catch(() => {});
  assert.equal(await settledWithin(third, 100), "pending", "the pool is full of outputs");

  await drain(first);
  assert.equal(await settledWithin(third, 100), "resolved");
  await Promise.all([drain(second), third.then(drain)]);
});

test("GUARD: deferring every read until the last call returns deadlocks", async () => {
  // The shape the making-progress note rules out: await every operation
  // before draining any. The four that fit hold their outputs, the fifth
  // waits for capacity, and the caller waits for the fifth.
  //
  // No implementation can rescue this — the bytes it needs back are the ones
  // the caller is holding — which is why the obligation is on the caller, and
  // why this is pinned rather than fixed.
  configure({ perCallBufferLimit: 1024, totalBufferLimit: 4096 });
  const aead = await key();
  const ops = Array.from({ length: 5 }, () =>
    aead.seal(NONCE, NO_AAD, streamOf(new Uint8Array(64))),
  );
  ops.forEach((op) => op.catch(() => {}));
  assert.equal(await settledWithin(Promise.all(ops), 150), "pending");

  // Draining what has returned releases the rest, so this is the caller's
  // shape rather than a wedged pool.
  const returned = await Promise.all(ops.slice(0, 4));
  await Promise.all(returned.map(drain));
  await ops[4].then(drain);
});

test("GUARD: withholding an admitted operation's input stalls a queued one", async () => {
  // The other half of the same obligation, on the input side. Four operations
  // fit; the fifth waits. Feeding only the fifth cannot release it, because
  // the four ahead of it hold the pool until their own inputs arrive.
  configure({ perCallBufferLimit: 1024, totalBufferLimit: 4096 });
  const aead = await key();
  const held = Array.from({ length: 5 }, heldStream);
  const ops = held.map((h) => aead.seal(NONCE, NO_AAD, h.stream));
  ops.forEach((op) => op.catch(() => {}));

  held[4].feed();
  assert.equal(await settledWithin(ops[4], 100), "pending");

  held.slice(0, 4).forEach((h) => h.feed());
  const returned = await Promise.all(ops.slice(0, 4));
  await Promise.all(returned.map(drain));
  await ops[4].then(drain);
});

test("configure updates only the limits it is given", async () => {
  const aead = await key();
  configure({ perCallBufferLimit: 4096, totalBufferLimit: 16384 });

  // Updating the pool alone must leave the per-call limit alone. Clobbering
  // it would derive a per-call limit of a quarter of the new pool — 512 — and
  // reject this 1024-byte input.
  configure({ totalBufferLimit: 2048 });
  await sealAndDrain(aead, streamOf(new Uint8Array(1024)));

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
  // arrived, leaving it stuck behind an operation the raised pool has room to
  // run alongside.
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

  configure({ totalBufferLimit: 4096 });
  assert.equal(
    await settledWithin(ops[1], 100),
    "resolved",
    "the waiter must be judged against the pool in force, not the one it arrived under",
  );

  await ops[1].then(drain);
  first.feed();
  await ops[0].then(drain);
});
