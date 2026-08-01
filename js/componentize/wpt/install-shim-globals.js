// Installs the shim as the `crypto`/`CryptoKey` globals.
//
// A separate module rather than a statement in runner.js because some
// vendored suites capture `crypto.subtle` at module top level
// (okp_importKey.js), and every import evaluates before the importing
// module's body: the globals must be in place when the suite bundles
// evaluate, so this module is imported textually before them.
import { crypto, CryptoKey } from "./js/componentize/webcrypto.js";

globalThis.crypto = crypto;
globalThis.CryptoKey = CryptoKey;
