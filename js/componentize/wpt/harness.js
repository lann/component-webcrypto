// A minimal testharness.js stand-in for running vendored WPT WebCryptoAPI
// tests inside a componentize-js guest (which has no browser globals).
//
// It implements only what those tests use — `promise_test`/`test`, the
// `assert_*` functions they call, `setup`/`done` (no-ops here), the
// `subsetTest` passthrough from WPT's /common/subset-tests.js, and the
// `btoa`/`self` globals — and it runs tests *sequentially*: each test's
// function is awaited before the next starts, which testharness.js permits
// and which keeps hundreds of stream-plumbed crypto calls deterministic.
//
// Results collect in module state; `drain()` awaits quiescence (tests may
// register more tests from promise callbacks) and `takeResults()` returns
// `{ name, status, message? }` records for the runner to classify.

const results = [];
let queue = Promise.resolve();
let registered = 0;
let settled = 0;

class AssertionError extends Error {}
// The eddsa/ecdsa suites discriminate assertion failures from operation
// errors by `instanceof AssertionError`, which testharness.js exposes.
globalThis.AssertionError = AssertionError;

function fail(message) {
  throw new AssertionError(message);
}

function record(name, run) {
  registered += 1;
  queue = queue.then(async () => {
    try {
      await run();
      results.push({ name, status: "PASS" });
    } catch (e) {
      results.push({ name, status: "FAIL", message: String((e && e.message) || e) });
    } finally {
      settled += 1;
    }
  });
}

globalThis.self = globalThis;

globalThis.setup = function () {};
globalThis.done = function () {};

globalThis.promise_test = function (fn, name) {
  record(name, () => fn({}));
};

globalThis.test = function (fn, name) {
  record(name, () => {
    fn({});
  });
};

// WPT's /common/subset-tests.js sharding helper: run everything.
globalThis.subsetTest = function (testFunc, ...args) {
  return testFunc(...args);
};

globalThis.assert_true = function (value, message) {
  if (value !== true) {
    fail(`assert_true: ${message ?? ""} (got ${value})`);
  }
};

globalThis.assert_false = function (value, message) {
  if (value !== false) {
    fail(`assert_false: ${message ?? ""} (got ${value})`);
  }
};

globalThis.assert_equals = function (actual, expected, message) {
  if (actual !== expected) {
    fail(`assert_equals: ${message ?? ""} (got ${String(actual)}, expected ${String(expected)})`);
  }
};

globalThis.assert_not_equals = function (actual, expected, message) {
  if (actual === expected) {
    fail(`assert_not_equals: ${message ?? ""} (got ${String(actual)})`);
  }
};

globalThis.assert_in_array = function (actual, expected, message) {
  if (!expected.includes(actual)) {
    fail(`assert_in_array: ${message ?? ""} (got ${String(actual)})`);
  }
};

globalThis.assert_array_equals = function (actual, expected, message) {
  if (actual.length !== expected.length) {
    fail(
      `assert_array_equals: ${message ?? ""} (lengths differ: got ${actual.length}, expected ${expected.length})`,
    );
  }
  for (let i = 0; i < actual.length; i += 1) {
    if (actual[i] !== expected[i]) {
      fail(
        `assert_array_equals: ${message ?? ""} (index ${i}: got ${String(actual[i])}, expected ${String(expected[i])})`,
      );
    }
  }
};

globalThis.assert_throws_dom = function (name, fn, description) {
  try {
    fn();
  } catch (e) {
    if (/** @type {{ name?: unknown }} */ (e)?.name === name) {
      return;
    }
    fail(`${description ?? "assert_throws_dom"}: expected ${name}, got ${e}`);
  }
  fail(`${description ?? "assert_throws_dom"}: expected ${name}, nothing thrown`);
};

globalThis.assert_throws_quotaexceedederror = function (fn, quota, requested, description) {
  globalThis.assert_throws_dom("QuotaExceededError", fn, description);
};

globalThis.promise_rejects_dom = function (test, name, promise, description) {
  return promise.then(
    () => {
      fail(`${description ?? "promise_rejects_dom"}: expected ${name}, nothing thrown`);
    },
    (e) => {
      if (/** @type {{ name?: unknown }} */ (e)?.name !== name) {
        fail(`${description ?? "promise_rejects_dom"}: expected ${name}, got ${e}`);
      }
    },
  );
};

globalThis.assert_implements_optional = function (condition, message) {
  // WPT's optional-feature marker (PRECONDITION_FAILED there); this harness
  // has two statuses, so a missing optional feature reports as a failure
  // and the classifiers keep such tests out of the asserted subset.
  if (!condition) {
    fail(message);
  }
};

globalThis.assert_unreached = function (message) {
  fail(`assert_unreached: ${message ?? ""}`);
};

// `btoa`, used by the vendored helpers to build JWK key data (the JWK tests
// themselves are outside this library's subset, but the data is constructed
// unconditionally).
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
// The ecdsa vectors clone their fixtures with `structuredClone`, which the
// componentize-js runtime lacks. This covers the shapes those fixtures are
// made of (plain objects, arrays, typed arrays, ArrayBuffers, primitives) —
// not the platform algorithm.
if (typeof globalThis.structuredClone !== "function") {
  globalThis.structuredClone = function clone(value) {
    if (value === null || typeof value !== "object") {
      return value;
    }
    if (ArrayBuffer.isView(value)) {
      return new (/** @type {any} */ (value.constructor))(value);
    }
    if (value instanceof ArrayBuffer) {
      return value.slice(0);
    }
    if (Array.isArray(value)) {
      return value.map(clone);
    }
    const out = {};
    for (const key of Object.keys(value)) {
      out[key] = clone(value[key]);
    }
    return out;
  };
}

globalThis.btoa = function (s) {
  let out = "";
  for (let i = 0; i < s.length; i += 3) {
    const codes = [s.charCodeAt(i), s.charCodeAt(i + 1), s.charCodeAt(i + 2)];
    for (const c of codes) {
      if (c > 255) {
        throw new Error("btoa: character out of range");
      }
    }
    const n = (codes[0] << 16) | ((codes[1] || 0) << 8) | (codes[2] || 0);
    out += B64[(n >> 18) & 63];
    out += B64[(n >> 12) & 63];
    out += i + 1 < s.length ? B64[(n >> 6) & 63] : "=";
    out += i + 2 < s.length ? B64[n & 63] : "=";
  }
  return out;
};

/**
 * Await test-queue quiescence: keeps waiting while settled tests trail
 * registered ones (test callbacks may register further tests).
 */
export async function drain() {
  for (;;) {
    await queue;
    if (settled === registered) {
      return;
    }
  }
}

export function takeResults() {
  return results.splice(0);
}
