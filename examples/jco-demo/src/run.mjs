// Driver for the Node host: transpile output is imported and the component's
// exported async `run` is invoked, then the summary is asserted.
//
// Run with:  npm run build:component && npm run transpile && npm test
import { demo } from "../generated/crypto-demo.js";

/**
 * Unwrap jco's representation of a WIT `result<string, string>` returned by
 * an exported function — a convention, not documented API, so it is
 * isolated here and version-anchored: validated against jco 1.26.1 /
 * jco-transpile 0.5.2. The ok value is returned directly and the err case
 * thrown (with a `{ tag, val }` result object tolerated too); revalidate
 * when bumping jco.
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

async function main() {
  const summary = await unwrapResult(() => demo.run());

  console.log("crypto-demo (Node / Web Crypto host) result:");
  console.log(`  ${summary}`);
  // The summary's declared count must agree with the checks it lists —
  // derived, not maintained (the guest is the single source of truth).
  const match = /^(\d+) checks passed: (.+)$/.exec(summary);
  if (!match) {
    throw new Error(`unexpected summary shape: ${summary}`);
  }
  const declared = Number(match[1]);
  const listed = match[2].split(", ").length;
  if (declared === 0 || declared !== listed) {
    throw new Error(`summary declares ${declared} checks but lists ${listed}: ${summary}`);
  }
  console.log("\nOK: every check passed against the Web Crypto host.");
}

main().then(
  () => process.exit(0),
  (err) => {
    console.error("crypto-demo failed:", err);
    process.exit(1);
  },
);
