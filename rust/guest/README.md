# lann-webcrypto-guest

Guest-side Rust library over the `lann:webcrypto` imports: the intended way
for Rust components to *consume* the package (the JS counterpart is
[`@lann/webcrypto-componentize`](../../js/componentize)). It binds the full
import surface once and wraps the key resources in newtypes, so consumers
do not re-implement the feed-a-stream-and-await plumbing the interfaces are
defined in terms of.

```rust
use lann_webcrypto_guest::{hmac_sha2, MacKeyOptions};
use lann_webcrypto_guest::hmac_sha2::Sha2Variant;

let key = hmac_sha2::generate_key(
    Sha2Variant::Sha256,
    None,
    MacKeyOptions { sign: true, verify: true, extractable: false },
)
.await?;
let tag = key.sign(b"payload").await?;
key.verify(b"payload", tag).await?;
```

Most consumers need no `lann:webcrypto` WIT of their own: link this crate
and call it, and the componentized binary imports exactly the interfaces it
uses (unused imports are stripped). The one sharp edge: never bind the same
interfaces with a second `generate!` without remapping them onto this
crate's `bindings` modules via wit-bindgen's `with:` option — two
expansions produce distinct, unconvertible resource types.

## Shape

- **Minting is free functions, one module per WIT minting interface**
  (`hmac_sha2`, `aes_gcm`, `hkdf`, `x25519`, …), taking plain-data options
  structs. **Operations are methods on the newtypes** (`Mac`, `Aead`,
  `DeriveInput`, …).
- **Operations take `impl Into<DataSource>`**: byte slices, owned buffers,
  a component-model `StreamReader<u8>` passed through unbuffered, and — as
  cargo features — `bytes` (`DataSource::from_buf`) and `futures-io`
  (`DataSource::from_reader`).
- **`seal`/`encrypt` return a lazy `Seal` future**: nothing runs until it
  is awaited, so a dropped `Seal` never draws from an internal-nonce key's
  budget, and the output is collected concurrently with the feed, serving
  incremental producers without deadlock.

## Errors

`Error` mirrors the WIT `types.error` variant (the `From` conversion is
exhaustive, so a new WIT case is a compile error here) plus two SDK-local
cases: `Read`, a failing `from_reader` source, and `ShortWrite`, a
provider that ended the input early and then claimed success. The
attribution precedence, per the package's stream-closure rule: `Read` wins
over everything (the operation only saw a truncated input), then the
operation's own error (a failing operation may close its input early), and
`ShortWrite` surfaces only under a success.

## How it is verified

The wrappers execute inside components only, so their harness is the
`crypto-demo` guest ([examples/crypto-demo](../../examples/crypto-demo)),
whose wrapper-layer checks run the same binary under all three
implementations — the Wasmtime host, the composed in-guest provider, and
the jco host. Algorithm correctness is the conformance suites' job
([conformance/](../../conformance)); the demo checks assert the wrapper
plumbing, including every `DataSource` variant and the `Error::Read`
precedence. The precedence itself is structural — a feed *fails* only by
`Error::Read`, while the operation rejecting input is an outcome the
success path requires to be `Complete` — with host-side unit tests over
the `ShortWrite` mapping (`cargo test -p lann-webcrypto-guest --all-features`).
