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

globalThis.assert_unreached = function (message) {
  fail(`assert_unreached: ${message ?? ""}`);
};

// `btoa`, used by the vendored helpers to build JWK key data (the JWK tests
// themselves are outside this library's subset, but the data is constructed
// unconditionally).
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
