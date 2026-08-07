// The suites' import object for `-I async` instantiation, shared by
// the Node and browser workers: the polymorph:webcrypto host
// interfaces discovered from the jco host module's lowercase namespace
// exports (the wildcard-map convention, applied at instantiate time —
// a new interface is a new namespace export, enumerated nowhere), the
// driver's test-context provider, and the caller's wasi shim
// namespaces (Node or browser build). Relative specifiers only: module
// Web Workers cannot see a page's import map.

import { bindImports } from "./node_modules/@polymorph/component-test-js/js/viewer/imports.mjs";
import * as webcrypto from "../../../js/jco/webcrypto.js";
import { Context } from "../context.js";

/** The camelCased namespace export's WIT interface name. */
const kebab = (name) => name.replace(/([a-z0-9])([A-Z])/g, "$1-$2").toLowerCase();

/** Build the full import object over the given wasi shim namespaces. */
export function suiteImports(wasi) {
  const sut = {};
  for (const [name, impl] of Object.entries(webcrypto)) {
    if (!/^[a-z]/.test(name) || typeof impl !== "object" || impl === null) {
      continue;
    }
    sut[`polymorph:webcrypto/${kebab(name)}`] = impl;
  }
  // The driver's own context (diagnostic sink wiring), not the
  // upstream default.
  sut["polymorph:test/test-context"] = { Context };
  return bindImports({ wasi, env: [], sut });
}

/** Instantiate one fresh suite: compiled cores by file name, plus the
 *  exported `tests` interface whichever spelling the transpile used. */
export async function instantiateSuite({ instantiate, modules, wasi }) {
  const instance = await instantiate((name) => modules.get(name), suiteImports(wasi));
  const tests =
    instance.tests ?? instance["polymorph:test/tests@0.1.0"] ?? instance["polymorph:test/tests"];
  if (!tests) {
    throw new Error(`suite instance exports no tests interface: ${Object.keys(instance)}`);
  }
  return tests;
}
