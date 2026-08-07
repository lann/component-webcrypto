// The browser worker's import-object module: the shared builder
// (host-imports.mjs) over the preview2-shim browser build. Loaded by
// the upstream browser-worker via URL, so every specifier is a server
// path over the repository-root server.
import { suiteImports as buildImports } from "./host-imports.mjs";
import * as cli from "./node_modules/@bytecodealliance/preview2-shim/lib/browser/cli.js";
import * as clocks from "./node_modules/@bytecodealliance/preview2-shim/lib/browser/clocks.js";
import * as io from "./node_modules/@bytecodealliance/preview2-shim/lib/browser/io.js";
import * as random from "./node_modules/@bytecodealliance/preview2-shim/lib/browser/random.js";
import * as filesystem from "./node_modules/@bytecodealliance/preview2-shim/lib/browser/filesystem.js";

/** The suites read no environment; the shim namespaces are the whole
 *  configuration. */
export async function suiteImports() {
  return buildImports({ cli, clocks, io, random, filesystem });
}
