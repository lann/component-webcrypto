// Driver for the Node host: transpile output is imported and the component's
// exported async `run` is invoked, then the summary is asserted.
//
// Run with:  npm run build:component && npm run transpile && npm test
import { demo } from "../generated/crypto-demo.js";

const EXPECTED = "13 checks passed";

async function main() {
  // jco represents `result<string, string>` by returning the ok value and
  // throwing on err; a `{ tag, val }` result object is tolerated too.
  let summary;
  try {
    summary = await demo.run();
  } catch (err) {
    throw new Error(`demo.run returned err: ${err?.payload ?? err?.val ?? err}`);
  }
  if (typeof summary === "object" && summary !== null && "tag" in summary) {
    if (summary.tag !== "ok") {
      throw new Error(`demo.run returned err: ${summary.val}`);
    }
    summary = summary.val;
  }

  console.log("crypto-demo (Node / Web Crypto host) result:");
  console.log(`  ${summary}`);
  if (!summary.includes(EXPECTED)) {
    throw new Error(`expected summary to contain "${EXPECTED}", got: ${summary}`);
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
