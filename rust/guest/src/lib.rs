//! Guest-side bindings and ergonomic helpers for the `lann:webcrypto`
//! interfaces.
//!
//! This crate is the intended way for Rust guest components to *consume*
//! `lann:webcrypto`: it binds the whole import surface once (the
//! [`bindings`] module) and wraps the key resources in newtypes whose
//! operations take a [`DataSource`] — a byte slice, an owned buffer, or a
//! component-model stream — so callers need none of the stream plumbing the
//! interfaces are defined in terms of.
//!
//! Most consumers need **no `lann:webcrypto` WIT at all**: link this crate
//! and call it, and the componentized binary imports exactly the interfaces
//! it uses (unused imports are stripped). Only list the imports in your own
//! world — remapping them onto this crate's [`bindings`] modules with
//! wit-bindgen's `with:` option — if your own interfaces name these types or
//! external tooling validates your world's shape. Do **not** bind the same
//! interfaces with a second `generate!` without that remapping: the two
//! expansions would produce distinct, unconvertible resource types, and the
//! newtypes here wrap only this crate's generation.
//!
//! # Cargo features
//!
//! - `bytes`: `DataSource::from_buf` feeds an operation from any
//!   `bytes::Buf`, chunk by chunk.
//! - `futures-io`: `DataSource::from_reader` feeds an operation from any
//!   `futures_io::AsyncRead`; read failures surface as [`Error::Read`].
//!
//! # Contract notes carried over from the WIT
//!
//! - **The wrappers hide streams, not the closure rule.** An operation's
//!   input stream ends no later than the operation completes, and only a
//!   failing operation may end it early; these helpers feed the source and
//!   await the result concurrently, reporting the operation's error over
//!   the feed's fate, so that contract is invisible here. Callers with
//!   needs beyond [`DataSource`] use the
//!   [`bindings`] resources directly with wit-bindgen's own stream
//!   primitives ([`wit_stream::new`], `StreamWriter::write_all`,
//!   [`StreamReader::collect`]).
//! - **Writer drop ends the message.** A stream's producer failing midway
//!   is indistinguishable from it finishing (the ABI carries no verdict at
//!   end-of-stream). Buffer-backed [`DataSource`]s own their whole input, so
//!   this only concerns stream-backed sources; see
//!   [`DataSource`]'s truncating-producer warning.
//! - **Implementations may bound input sizes.** Hosts enforce buffering
//!   limits as recoverable [`Error::Other`] values (see the WIT
//!   `types.error` docs); nothing here retries or special-cases them.
//! - **Nonces are the caller's problem only on `aead`.** Prefer
//!   [`AeadInternalNonce`] (minted by [`aes_gcm_internal_nonce`], or by
//!   `xchacha20_poly1305_internal_nonce` under the `chacha` cargo
//!   feature), whose nonces are
//!   implementation-managed and carried in the sealed message.

#![deny(missing_docs)]

use std::borrow::Cow;
use std::fmt;

use wit_bindgen::StreamWriter;

/// Re-export of the `wit-bindgen` crate this crate's bindings were generated
/// with, so consumers can name its runtime types (streams, futures) without
/// depending on — and version-matching — `wit-bindgen` themselves.
pub use wit_bindgen;
/// The component-model byte-stream reader, as returned by [`Aead::seal`] and
/// friends and accepted by [`DataSource`].
pub use wit_bindgen::StreamReader;

mod generated {
    #![allow(missing_docs)]
    // Two mutually exclusive expansions rather than one parameterized by
    // the cargo feature: `generate!`'s `features` list is static, and the
    // arms must stay option-for-option identical apart from it.
    #[cfg(feature = "chacha")]
    wit_bindgen::generate!({
        path: "wit",
        features: ["chacha20-poly1305", "xchacha20-poly1305"],
        world: "imports",
        generate_all,
        pub_export_macro: false,
    });
    #[cfg(not(feature = "chacha"))]
    wit_bindgen::generate!({
        path: "wit",
        world: "imports",
        generate_all,
        pub_export_macro: false,
    });
}

/// The generated bindings for the full `lann:webcrypto` import surface.
///
/// The newtype wrappers cover the common cases; these are the escape hatch
/// for callers driving the streams themselves and for passing resources
/// through a consumer's own interfaces (via [`Mac::into_raw`] and friends).
pub mod bindings {
    // `aes` and `sha2` are here for their *types*: they define
    // `aes-variant` and `sha2-variant`, which the minting interfaces only
    // alias, and rustdoc renders an alias into a private module as an empty
    // enum.
    pub use super::generated::lann::webcrypto::{
        aead, aead_internal_nonce, aes, aes_cbc, aes_ctr, aes_gcm, aes_gcm_internal_nonce, bytes,
        cipher, derivation, digest, ecdsa_sign, ecdsa_verify, ed25519_sign, ed25519_verify, hkdf,
        hkdf_sha1, hkdf_sha2, hmac_sha1, hmac_sha2, key_agreement, mac, pbkdf2, pbkdf2_sha1,
        pbkdf2_sha2, sha1_checked, sha2, signature, types, x25519,
    };
    #[cfg(feature = "chacha")]
    pub use super::generated::lann::webcrypto::{
        chacha20_poly1305, xchacha20_poly1305, xchacha20_poly1305_internal_nonce,
    };
}

pub use generated::wit_stream;

// --- error ---------------------------------------------------------------------

/// Errors surfaced by key creation and cryptographic operations.
///
/// Mirrors the WIT `types.error` variant (see the doc comments in
/// `wit/webcrypto.wit` for the full contracts), plus [`Error::Read`] for
/// failures of a caller-supplied [`DataSource`] producer. Misuse of the API
/// is unrepresentable by construction — operations are one-shot calls on
/// immutable key resources — and so has no variant here.
///
/// `#[non_exhaustive]`: this enum carries [`Error::Read`] in addition to the
/// WIT cases, so it grows independently of the package's own rule that a new
/// `types.error` case is semver-major. The `From` conversion below is
/// exhaustive over the WIT variant, so a case added there is a compile error
/// here rather than a silent fallthrough.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The supplied key material is invalid for the algorithm (for example,
    /// a wrong-length raw key, or one rejected by an implementation's
    /// key-length policy). The string is human-readable.
    InvalidKey(String),
    /// The supplied nonce is invalid for the algorithm (for example, a
    /// wrong-length AES-GCM nonce). The string is human-readable.
    InvalidNonce(String),
    /// Verification failed: the MAC tag, the signature, or the ciphertext or
    /// its associated data did not verify under the key. Deliberately
    /// carries no detail, so implementations cannot leak *why* verification
    /// failed.
    AuthenticationFailed,
    /// The key was created with `extractable` false, so its material cannot
    /// be exported.
    NotExtractable,
    /// The request was well-formed, but the implementation does not serve
    /// the requested algorithm parameters. The string is human-readable.
    Unsupported(String),
    /// The key does not permit the requested operation: it was minted (or
    /// arrived from a platform keystore) with the operation's usage
    /// disabled. The string names the refused operation.
    NotPermitted(String),
    /// The key's nonce budget is exhausted: the implementation can no longer
    /// guarantee nonce uniqueness for this key. The key remains valid for
    /// `open`; mint a fresh key to continue sealing.
    KeyExhausted,
    /// An implementation-specific operational failure (an external keystore
    /// that cannot complete the operation, an input exceeding a buffering
    /// limit, …). The string is human-readable.
    Other(String),
    /// A named condition outside the WIT `error` variant's closed set,
    /// identified by the (`origin`, `name`) pair — the only branchable
    /// identity; `message` is human-readable prose, never contract.
    /// Handle an unrecognized pair as [`Error::Other`]. Known pairs have
    /// constants in [`extension`].
    Extension(bindings::types::ExtensionError),
    /// A caller-supplied [`DataSource`] producer failed while being fed into
    /// the operation (see `DataSource::from_reader`). The operation's own
    /// result is discarded: it was computed over a truncated input.
    Read(std::io::Error),
    /// The operation succeeded without accepting the whole source: the
    /// provider closed the stream's read end early and then reported
    /// success. The stream-closure rule permits ending the input early
    /// only when the operation fails (a failing operation's own error is
    /// what these wrappers report), so this indicates a defective
    /// provider, not a condition to retry.
    ShortWrite,
}

/// The known extension-error conditions, as (`origin`, `name`) constants
/// for matching against [`Error::Extension`].
pub mod extension {
    /// The `origin` of conditions the `lann:webcrypto` package defines.
    pub const LANN_WEBCRYPTO: &str = "lann:webcrypto";
    /// `sha1-checked`'s collision condition: a rejecting digest's input
    /// carried a SHA-1 collision attack pattern.
    pub const COLLISION_DETECTED: &str = "collision-detected";
}

impl From<bindings::types::Error> for Error {
    fn from(error: bindings::types::Error) -> Self {
        use bindings::types::Error as Raw;
        match error {
            Raw::InvalidKey(detail) => Error::InvalidKey(detail),
            Raw::InvalidNonce(detail) => Error::InvalidNonce(detail),
            Raw::AuthenticationFailed => Error::AuthenticationFailed,
            Raw::NotExtractable => Error::NotExtractable,
            Raw::Unsupported(detail) => Error::Unsupported(detail),
            Raw::NotPermitted(detail) => Error::NotPermitted(detail),
            Raw::KeyExhausted => Error::KeyExhausted,
            Raw::Other(detail) => Error::Other(detail),
            Raw::Extension(ext) => Error::Extension(ext),
        }
    }
}

/// Renders the WIT cases case-name-first — `invalid-key: <detail>` — plus
/// the [`Error::Read`] case this type adds.
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKey(detail) => write!(f, "invalid-key: {detail}"),
            Error::InvalidNonce(detail) => write!(f, "invalid-nonce: {detail}"),
            Error::AuthenticationFailed => write!(f, "authentication-failed"),
            Error::NotExtractable => write!(f, "not-extractable"),
            Error::Unsupported(detail) => write!(f, "unsupported: {detail}"),
            Error::NotPermitted(detail) => write!(f, "not-permitted: {detail}"),
            Error::KeyExhausted => write!(f, "key-exhausted"),
            Error::Other(detail) => write!(f, "other: {detail}"),
            Error::Extension(ext) => write!(
                f,
                "extension({origin}, {name}): {message}",
                origin = ext.origin,
                name = ext.name,
                message = ext.message,
            ),
            Error::Read(error) => write!(f, "data source read failed: {error}"),
            Error::ShortWrite => write!(
                f,
                "short write: the operation stopped accepting input before the \
                 source was fully written"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Read(error) => Some(error),
            _ => None,
        }
    }
}

// --- data sources ----------------------------------------------------------------

/// The input to a wrapped operation: anything this crate knows how to feed
/// into a WIT `stream<u8>`.
///
/// Operation methods take `impl Into<DataSource<'_>>`, so byte slices, owned
/// buffers, and streams received from other components all work directly:
///
/// - `&[u8]`, `&[u8; N]`, `Vec<u8>`, `&Vec<u8>`, [`Cow<'a, [u8]>`](Cow) —
///   buffered sources. Owned data is moved and written whole, never copied;
///   borrowed data is fed chunk by chunk through one reusable buffer, so a
///   large input is never duplicated whole (the ABI's per-chunk copy into
///   an owned buffer is unavoidable).
/// - [`StreamReader<u8>`] — passed through to the operation as-is, without
///   buffering.
/// - `DataSource::from_buf` (feature `bytes`) — fed chunk by chunk.
/// - `DataSource::from_reader` (feature `futures-io`) — pumped
///   incrementally; read failures surface as [`Error::Read`].
///
/// # Warning: truncating producers
///
/// Dropping a stream's writer is its only end-of-input signal and carries no
/// verdict, so a producer that fails midway is indistinguishable *on the
/// wire* from one that finished — the operation correctly computes over the
/// delivered prefix. Buffer-backed sources own their whole input and are
/// immune. For a [`StreamReader<u8>`] fed by another component, convey
/// completeness in-band (e.g. length framing) or discard the result on
/// producer failure. A `DataSource::from_reader` source is handled for
/// you: its failure is observed locally and reported as [`Error::Read`]
/// instead of the operation's result.
pub struct DataSource<'a>(Inner<'a>);

enum Inner<'a> {
    Bytes(Cow<'a, [u8]>),
    Stream(StreamReader<u8>),
    #[cfg(feature = "bytes")]
    Buf(Box<dyn ::bytes::Buf + 'a>),
    #[cfg(feature = "futures-io")]
    Reader(std::pin::Pin<Box<dyn futures_io::AsyncRead + 'a>>),
}

impl<'a> From<&'a [u8]> for DataSource<'a> {
    fn from(data: &'a [u8]) -> Self {
        Self(Inner::Bytes(Cow::Borrowed(data)))
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for DataSource<'a> {
    fn from(data: &'a [u8; N]) -> Self {
        Self(Inner::Bytes(Cow::Borrowed(data)))
    }
}

impl From<Vec<u8>> for DataSource<'_> {
    fn from(data: Vec<u8>) -> Self {
        Self(Inner::Bytes(Cow::Owned(data)))
    }
}

impl<'a> From<&'a Vec<u8>> for DataSource<'a> {
    fn from(data: &'a Vec<u8>) -> Self {
        Self(Inner::Bytes(Cow::Borrowed(data)))
    }
}

impl<'a> From<Cow<'a, [u8]>> for DataSource<'a> {
    fn from(data: Cow<'a, [u8]>) -> Self {
        Self(Inner::Bytes(data))
    }
}

impl From<StreamReader<u8>> for DataSource<'_> {
    fn from(stream: StreamReader<u8>) -> Self {
        Self(Inner::Stream(stream))
    }
}

impl<'a> DataSource<'a> {
    /// A source that feeds the operation from `buf`, chunk by chunk.
    ///
    /// `Buf` is infallible, so this source cannot produce [`Error::Read`].
    #[cfg(feature = "bytes")]
    pub fn from_buf(buf: impl ::bytes::Buf + 'a) -> Self {
        Self(Inner::Buf(Box::new(buf)))
    }

    /// A source that pumps the operation's input from `reader` until
    /// end-of-file.
    ///
    /// A read failure aborts the feed and the operation reports
    /// [`Error::Read`] — never the result computed over the truncated
    /// prefix.
    #[cfg(feature = "futures-io")]
    pub fn from_reader(reader: impl futures_io::AsyncRead + 'a) -> Self {
        Self(Inner::Reader(Box::pin(reader)))
    }
}

// --- operation plumbing ---------------------------------------------------------

/// The chunk size the incremental feeders copy through their reusable
/// scratch buffer, bounding a feed's extra memory to one chunk.
const FEED_CHUNK: usize = 8192;

/// A feeder's outcome, distinct from its *failure* ([`Error::Read`]): a
/// rejected write is not itself an error — the closure rule permits a
/// failing operation to stop reading — so its meaning depends on the
/// operation's result.
#[must_use]
enum Feed {
    /// Every byte was written.
    Complete,
    /// The operation stopped accepting input partway.
    Rejected,
}

impl Feed {
    /// The success-path requirement: a completed operation promises it
    /// consumed the whole input, so rejection under success is the defect
    /// [`Error::ShortWrite`] names.
    fn require_complete(self) -> Result<(), Error> {
        match self {
            Feed::Complete => Ok(()),
            Feed::Rejected => Err(Error::ShortWrite),
        }
    }
}

impl Inner<'_> {
    /// Feed this source into `tx`, then drop the writer to end the stream.
    /// The error is always [`Error::Read`] — the only way a feed *fails*;
    /// the operation rejecting input is an outcome, not an error.
    async fn feed(self, mut tx: StreamWriter<u8>) -> Result<Feed, Error> {
        match self {
            // Pass-through sources never reach the feeder.
            Inner::Stream(_) => unreachable!("stream sources are passed through"),
            Inner::Bytes(Cow::Owned(data)) => {
                let leftover = tx.write_all(data).await;
                if leftover.is_empty() {
                    Ok(Feed::Complete)
                } else {
                    Ok(Feed::Rejected)
                }
            }
            // A borrowed buffer is never duplicated whole: it is fed in
            // chunks through one reusable allocation (`write_all` returns
            // its argument's allocation, emptied on success), so the feed
            // costs one chunk of extra memory and the ABI's unavoidable
            // per-chunk copy.
            Inner::Bytes(Cow::Borrowed(data)) => {
                let mut scratch = Vec::new();
                for chunk in data.chunks(FEED_CHUNK) {
                    scratch.extend_from_slice(chunk);
                    scratch = tx.write_all(scratch).await;
                    if !scratch.is_empty() {
                        return Ok(Feed::Rejected);
                    }
                }
                Ok(Feed::Complete)
            }
            #[cfg(feature = "bytes")]
            Inner::Buf(mut buf) => {
                use ::bytes::Buf as _;
                // As for borrowed bytes: one reusable scratch buffer, one
                // copy per source-native chunk.
                let mut scratch = Vec::new();
                while buf.has_remaining() {
                    let chunk = buf.chunk();
                    let n = chunk.len();
                    scratch.extend_from_slice(chunk);
                    buf.advance(n);
                    scratch = tx.write_all(scratch).await;
                    if !scratch.is_empty() {
                        return Ok(Feed::Rejected);
                    }
                }
                Ok(Feed::Complete)
            }
            #[cfg(feature = "futures-io")]
            Inner::Reader(mut reader) => {
                // As for borrowed bytes: one reusable scratch buffer, one
                // copy per chunk (out of the read buffer `poll_read`
                // requires).
                let mut chunk = [0u8; FEED_CHUNK];
                let mut scratch = Vec::new();
                loop {
                    let n = std::future::poll_fn(|cx| reader.as_mut().poll_read(cx, &mut chunk))
                        .await
                        .map_err(Error::Read)?;
                    if n == 0 {
                        return Ok(Feed::Complete);
                    }
                    scratch.extend_from_slice(&chunk[..n]);
                    scratch = tx.write_all(scratch).await;
                    if !scratch.is_empty() {
                        return Ok(Feed::Rejected);
                    }
                }
            }
        }
    }
}

/// Run the operation built by `op` over `source`: pass a stream source
/// through directly, or mint a stream pair and feed the source concurrently
/// with the operation (per the closure rule, the feed settles no later
/// than the operation). The joined outcome resolves one precedence rule
/// per statement: a source failure outranks everything (the operation only
/// saw a truncated input); then the operation's result is authoritative;
/// and a completed operation must have consumed the whole input.
async fn run_sourced<T, F>(
    source: DataSource<'_>,
    op: impl FnOnce(StreamReader<u8>) -> F,
) -> Result<T, Error>
where
    F: std::future::Future<Output = Result<T, bindings::types::Error>>,
{
    match source.0 {
        Inner::Stream(rx) => op(rx).await.map_err(Error::from),
        inner => {
            let (tx, rx) = wit_stream::new();
            let (result, fed) = futures::join!(op(rx), inner.feed(tx));
            let fed = fed?;
            let value = result?;
            fed.require_complete()?;
            Ok(value)
        }
    }
}

/// A pending `seal`, returned by [`Aead::seal`] and
/// [`AeadInternalNonce::seal`].
///
/// Nothing runs until this is polled: the operation starts on the first
/// `await`, so a `Seal` that is dropped unused never calls the
/// implementation — and so never draws from an internal-nonce key's budget.
///
/// Awaiting it yields the whole sealed message. It is a [`Future`] rather
/// than an `async fn`'s anonymous one so that it drops straight into
/// [`futures::join!`], which is the shape the package's making-progress rule
/// asks callers for: several operations in flight, all of them making
/// progress.
///
/// `seal` is the one operation in the package whose result may arrive before
/// its input is consumed — the WIT permits producing the sealed message
/// incrementally — so the collect runs *concurrently* with the feed. Awaiting
/// the operation first and reading the stream afterwards would deadlock
/// against a provider that does so.
#[must_use = "a Seal does nothing until it is awaited"]
pub struct Seal<'a> {
    state: SealState<'a>,
}

type LocalBoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + 'a>>;

/// Starts the operation over the readable end of a freshly minted stream.
type StartSeal<'a> = Box<
    dyn FnOnce(
            StreamReader<u8>,
        ) -> LocalBoxFuture<'a, Result<StreamReader<u8>, bindings::types::Error>>
        + 'a,
>;

enum SealState<'a> {
    Ready(DataSource<'a>, StartSeal<'a>),
    Running(LocalBoxFuture<'a, Result<Vec<u8>, Error>>),
    Done,
}

impl<'a> Seal<'a> {
    fn new(source: DataSource<'a>, start: StartSeal<'a>) -> Self {
        Self {
            state: SealState::Ready(source, start),
        }
    }
}

impl std::future::Future for Seal<'_> {
    type Output = Result<Vec<u8>, Error>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        // `Seal` is `Unpin`: every field is a `Box` or a `Pin<Box<_>>`.
        let this = self.get_mut();
        if let SealState::Ready(..) = this.state {
            let SealState::Ready(source, start) =
                std::mem::replace(&mut this.state, SealState::Done)
            else {
                unreachable!("just matched Ready")
            };
            this.state = SealState::Running(seal_and_collect(source, start));
        }
        match &mut this.state {
            SealState::Running(running) => running.as_mut().poll(cx),
            SealState::Done => panic!("Seal polled after completion"),
            SealState::Ready(..) => unreachable!("started above"),
        }
    }
}

/// Feed the source and collect the sealed message concurrently.
fn seal_and_collect<'a>(
    source: DataSource<'a>,
    start: StartSeal<'a>,
) -> LocalBoxFuture<'a, Result<Vec<u8>, Error>> {
    Box::pin(async move {
        match source.0 {
            // A caller-supplied stream is fed by whoever owns its writer, so
            // there is nothing to run concurrently here.
            Inner::Stream(rx) => {
                let sealed = start(rx).await.map_err(Error::from)?;
                Ok(sealed.collect().await)
            }
            inner => {
                let (tx, rx) = wit_stream::new();
                let sealed = async {
                    let stream = start(rx).await.map_err(Error::from)?;
                    Ok::<_, Error>(stream.collect().await)
                };
                let (result, fed) = futures::join!(sealed, inner.feed(tx));
                let fed = fed?;
                let value = result?;
                fed.require_complete()?;
                Ok(value)
            }
        }
    })
}

// --- key options ----------------------------------------------------------------

/// Mint-time policy for a [`Mac`] key: the plain-data counterpart of the
/// WIT `mac.mac-key-options` resource, which the minting functions
/// construct from it per call.
///
/// Follows the package-wide options contract: the default grants nothing,
/// every field is opt-in, and a mint with no usage enabled fails
/// [`Error::NotPermitted`].
#[derive(Clone, Copy, Debug, Default)]
pub struct MacKeyOptions {
    /// Whether the minted key may `sign`.
    pub sign: bool,
    /// Whether the minted key may `verify`.
    pub verify: bool,
    /// Whether the minted key's material may be exported.
    pub extractable: bool,
}

impl MacKeyOptions {
    /// The WIT options resource carrying this policy.
    pub(crate) fn lower(self) -> bindings::mac::MacKeyOptions {
        let options = bindings::mac::MacKeyOptions::new();
        options.can_sign(self.sign);
        options.can_verify(self.verify);
        options.extractable(self.extractable);
        options
    }
}

/// Mint-time policy for an [`Aead`] key. See [`MacKeyOptions`] for the
/// options contract; `wrap`/`unwrap` are recorded ahead of operations (the
/// package has no wrap operation yet).
#[derive(Clone, Copy, Debug, Default)]
pub struct AeadKeyOptions {
    /// Whether the minted key may `seal`.
    pub seal: bool,
    /// Whether the minted key may `open`.
    pub open: bool,
    /// Whether the minted key may wrap keys.
    pub wrap: bool,
    /// Whether the minted key may unwrap keys.
    pub unwrap: bool,
    /// Whether the minted key's material may be exported.
    pub extractable: bool,
}

impl AeadKeyOptions {
    /// The WIT options resource carrying this policy.
    pub(crate) fn lower(self) -> bindings::aead::AeadKeyOptions {
        let options = bindings::aead::AeadKeyOptions::new();
        options.can_seal(self.seal);
        options.can_open(self.open);
        options.can_wrap(self.wrap);
        options.can_unwrap(self.unwrap);
        options.extractable(self.extractable);
        options
    }
}

/// Mint-time policy for a [`CipherKey`] key. See [`MacKeyOptions`] for the
/// options contract; `wrap`/`unwrap` are recorded ahead of operations.
#[derive(Clone, Copy, Debug, Default)]
pub struct CipherKeyOptions {
    /// Whether the minted key may `encrypt`.
    pub encrypt: bool,
    /// Whether the minted key may `decrypt`.
    pub decrypt: bool,
    /// Whether the minted key may wrap keys.
    pub wrap: bool,
    /// Whether the minted key may unwrap keys.
    pub unwrap: bool,
    /// Whether the minted key's material may be exported.
    pub extractable: bool,
}

impl CipherKeyOptions {
    /// The WIT options resource carrying this policy.
    pub(crate) fn lower(self) -> bindings::cipher::CipherKeyOptions {
        let options = bindings::cipher::CipherKeyOptions::new();
        options.can_encrypt(self.encrypt);
        options.can_decrypt(self.decrypt);
        options.can_wrap(self.wrap);
        options.can_unwrap(self.unwrap);
        options.extractable(self.extractable);
        options
    }
}

/// Mint-time policy for an [`AeadInternalNonce`] key. See [`MacKeyOptions`]
/// for the options contract.
#[derive(Clone, Copy, Debug, Default)]
pub struct InternalNonceKeyOptions {
    /// Whether the minted key may `seal`.
    pub seal: bool,
    /// Whether the minted key may `open`.
    pub open: bool,
    /// Whether the minted key's material may be exported.
    pub extractable: bool,
}

impl InternalNonceKeyOptions {
    /// The WIT options resource carrying this policy.
    pub(crate) fn lower(self) -> bindings::aead_internal_nonce::InternalNonceKeyOptions {
        let options = bindings::aead_internal_nonce::InternalNonceKeyOptions::new();
        options.can_seal(self.seal);
        options.can_open(self.open);
        options.extractable(self.extractable);
        options
    }
}

/// Mint-time policy for a [`SigningKey`]. See [`MacKeyOptions`] for the
/// options contract; `sign` is the sole usage, so it must be enabled for a
/// mint to succeed.
#[derive(Clone, Copy, Debug, Default)]
pub struct SigningKeyOptions {
    /// Whether the minted key may `sign`.
    pub sign: bool,
    /// Whether the minted key's material may be exported (by future
    /// format-specific exports; there is no export operation today).
    pub extractable: bool,
}

impl SigningKeyOptions {
    /// The WIT options resource carrying this policy.
    pub(crate) fn lower(self) -> bindings::signature::SigningKeyOptions {
        let options = bindings::signature::SigningKeyOptions::new();
        options.can_sign(self.sign);
        options.extractable(self.extractable);
        options
    }
}

/// Mint-time policy for a derivation base secret ([`Ikm`] or [`Password`]).
/// See [`MacKeyOptions`] for the options contract. The grants are copied
/// onto every [`DeriveInput`] built on the secret; parameterization
/// neither grants nor revokes.
#[derive(Clone, Copy, Debug, Default)]
pub struct DeriveOptions {
    /// Whether inputs built on this secret may yield raw bits through
    /// [`DeriveInput::derive_bits`] — and, because an exportable key is
    /// bits disclosure by other means, whether they may mint
    /// *extractable* keys.
    pub derive_bits: bool,
    /// Whether inputs built on this secret may mint keys through the
    /// target interfaces' `derive_key` (e.g. [`hmac_sha2::derive_key`]).
    pub derive_key: bool,
}

impl DeriveOptions {
    /// The WIT options resource carrying this policy.
    pub(crate) fn lower(self) -> bindings::derivation::DeriveOptions {
        let options = bindings::derivation::DeriveOptions::new();
        options.can_derive_bits(self.derive_bits);
        options.can_derive_key(self.derive_key);
        options
    }
}

/// Mint-time policy for an [`AgreementSecretKey`]. See [`MacKeyOptions`]
/// for the options contract; the derive grants are copied onto every
/// [`DeriveInput`] the key [`agree`](AgreementSecretKey::agree)s
/// (WebCrypto's model: derive usages live on the secret key).
#[derive(Clone, Copy, Debug, Default)]
pub struct AgreementKeyOptions {
    /// Whether inputs agreed by the key may yield raw bits. See
    /// [`DeriveOptions::derive_bits`].
    pub derive_bits: bool,
    /// Whether inputs agreed by the key may mint keys. See
    /// [`DeriveOptions::derive_key`].
    pub derive_key: bool,
    /// Whether the secret key's material may be exported.
    pub extractable: bool,
}

impl AgreementKeyOptions {
    /// The WIT options resource carrying this policy.
    pub(crate) fn lower(self) -> bindings::key_agreement::AgreementKeyOptions {
        let options = bindings::key_agreement::AgreementKeyOptions::new();
        options.can_derive_bits(self.derive_bits);
        options.can_derive_key(self.derive_key);
        options.extractable(self.extractable);
        options
    }
}

// --- newtypes ------------------------------------------------------------------

/// Generate the shared newtype plumbing: constructors, raw accessors, and
/// `From` in both directions.
macro_rules! newtype_common {
    ($name:ident, $raw:ty, $doc_res:literal) => {
        impl $name {
            #[doc = concat!("Wrap a raw `", $doc_res, "` resource.")]
            pub fn from_raw(raw: $raw) -> Self {
                Self(raw)
            }

            #[doc = concat!("Borrow the raw `", $doc_res, "` resource.")]
            pub fn as_raw(&self) -> &$raw {
                &self.0
            }

            #[doc = concat!("Unwrap into the raw `", $doc_res, "` resource.")]
            pub fn into_raw(self) -> $raw {
                self.0
            }
        }

        impl From<$raw> for $name {
            fn from(raw: $raw) -> Self {
                Self(raw)
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }
    };
}

/// A `mac.mac-key`: a message-authentication-code key, bound to one
/// algorithm at creation.
pub struct Mac(bindings::mac::MacKey);
newtype_common!(Mac, bindings::mac::MacKey, "mac-key");

impl Mac {
    /// Compute the authentication tag over `data`.
    ///
    /// Fails only for operational reasons ([`Error::Other`], or
    /// [`Error::Read`] for a failing `DataSource::from_reader` source) —
    /// never for misuse, which is unrepresentable.
    pub async fn sign(&self, data: impl Into<DataSource<'_>>) -> Result<Vec<u8>, Error> {
        run_sourced(data.into(), |rx| self.0.sign(rx)).await
    }

    /// Verify `tag` over `data`, in constant time.
    ///
    /// Fails closed with [`Error::AuthenticationFailed`] if the tag does not
    /// verify — deliberately a `Result` rather than a `bool`: an ignored
    /// boolean fails open, a dropped `Result` does not.
    pub async fn verify(
        &self,
        data: impl Into<DataSource<'_>>,
        tag: impl Into<Cow<'_, [u8]>>,
    ) -> Result<(), Error> {
        let tag = tag.into().into_owned();
        run_sourced(data.into(), |rx| self.0.verify(rx, tag)).await
    }

    /// The name of the key's algorithm family, e.g. `"HMAC"` — WebCrypto's
    /// `KeyAlgorithm.name`, spelled as the [W3C Web Cryptography API
    /// algorithm registry](https://www.w3.org/TR/WebCryptoAPI/#algorithm-overview)
    /// spells it.
    pub fn algorithm_name(&self) -> String {
        self.0.algorithm_name()
    }

    /// The registry name of the digest the algorithm is parameterized over,
    /// e.g. `"SHA-256"` for HMAC-SHA-256 (WebCrypto's
    /// `HmacKeyAlgorithm.hash`, spelled per the same registry as
    /// [`algorithm_name`](Self::algorithm_name)). `None` for MAC algorithms
    /// not built on a digest.
    pub fn algorithm_hash(&self) -> Option<String> {
        self.0.algorithm_hash()
    }

    /// The key length in bits (WebCrypto's `HmacKeyAlgorithm.length`: the
    /// length of the key material).
    pub fn algorithm_length(&self) -> u32 {
        self.0.algorithm_length()
    }

    /// Whether [`export_key_raw`](Self::export_key_raw) may return the key
    /// material.
    ///
    /// Asking is not the same as exporting: interrogating extractability
    /// through [`export_key_raw`](Self::export_key_raw) alone would hand you the
    /// material whenever the answer is yes.
    pub fn extractable(&self) -> bool {
        self.0.extractable()
    }

    /// Whether the key permits [`sign`](Self::sign) — the usage recorded
    /// at mint. A refused operation fails [`Error::NotPermitted`].
    pub fn can_sign(&self) -> bool {
        self.0.can_sign()
    }

    /// Whether the key permits [`verify`](Self::verify). See
    /// [`can_sign`](Self::can_sign).
    pub fn can_verify(&self) -> bool {
        self.0.can_verify()
    }

    /// The raw key material; fails with [`Error::NotExtractable`] unless the
    /// key was minted extractable. Extractability is an API property, not a
    /// physical one: the guarantee is that components holding only the
    /// handle cannot obtain the material through this API.
    pub async fn export_key_raw(&self) -> Result<Vec<u8>, Error> {
        self.0.export_key_raw().await.map_err(Error::from)
    }

    /// The key as an RFC 7517 `oct` JSON Web Key (JSON text), behind the
    /// same extractability gate as [`export_key_raw`](Self::export_key_raw).
    pub async fn export_key_jwk(&self) -> Result<String, Error> {
        self.0.export_key_jwk().await.map_err(Error::from)
    }
}

/// An `aead.aead-key`: caller-nonce authenticated encryption with
/// associated data.
///
/// Prefer [`AeadInternalNonce`] unless interop requires an externally
/// specified nonce layout: nonce reuse under one key is catastrophic, and
/// this type's [`seal`](Self::seal) leaves nonce uniqueness entirely to you.
pub struct Aead(bindings::aead::AeadKey);
newtype_common!(Aead, bindings::aead::AeadKey, "aead-key");

impl Aead {
    /// Encrypt and authenticate `plaintext` under `nonce` and `aad`,
    /// yielding the ciphertext followed by the authentication tag.
    ///
    /// Returns a [`Seal`], which starts the operation when awaited.
    ///
    /// **The caller is responsible for nonce uniqueness per key.** Reusing a
    /// nonce under one key defeats the algorithm's confidentiality and
    /// authenticity guarantees; prefer [`AeadInternalNonce`], which makes
    /// reuse unrepresentable.
    pub fn seal<'a>(
        &'a self,
        nonce: impl Into<Cow<'a, [u8]>>,
        aad: impl Into<Cow<'a, [u8]>>,
        plaintext: impl Into<DataSource<'a>>,
    ) -> Seal<'a> {
        let (nonce, aad) = (nonce.into().into_owned(), aad.into().into_owned());
        Seal::new(
            plaintext.into(),
            Box::new(move |rx| Box::pin(self.0.seal(nonce, aad, None, rx))),
        )
    }

    /// [`seal`](Self::seal) with an explicit tag size in bytes, for
    /// algorithms whose tag size is a per-call parameter (AES-GCM's set is
    /// 4, 8, 12, 13, 14, 15, or 16; other algorithms fix 16). Short tags
    /// weaken the forgery bound; prefer [`seal`](Self::seal), which uses
    /// the algorithm default ([`tag_size`](Self::tag_size)).
    pub fn seal_with_tag_size<'a>(
        &'a self,
        nonce: impl Into<Cow<'a, [u8]>>,
        aad: impl Into<Cow<'a, [u8]>>,
        tag_size: u8,
        plaintext: impl Into<DataSource<'a>>,
    ) -> Seal<'a> {
        let (nonce, aad) = (nonce.into().into_owned(), aad.into().into_owned());
        Seal::new(
            plaintext.into(),
            Box::new(move |rx| Box::pin(self.0.seal(nonce, aad, Some(tag_size), rx))),
        )
    }

    /// Decrypt and verify `ciphertext` (ciphertext followed by tag, as
    /// produced by [`seal`](Self::seal)) under `nonce` and `aad`.
    ///
    /// The stream is handed back only after the whole input is consumed and
    /// the tag verified: `Ok` *is* the authentication statement, and
    /// unverified plaintext is never observable. Fails closed with
    /// [`Error::AuthenticationFailed`] if verification fails.
    pub async fn open(
        &self,
        nonce: impl Into<Cow<'_, [u8]>>,
        aad: impl Into<Cow<'_, [u8]>>,
        ciphertext: impl Into<DataSource<'_>>,
    ) -> Result<StreamReader<u8>, Error> {
        let (nonce, aad) = (nonce.into().into_owned(), aad.into().into_owned());
        run_sourced(ciphertext.into(), |rx| self.0.open(nonce, aad, None, rx)).await
    }

    /// [`open`](Self::open) with an explicit tag size in bytes (the size
    /// the message was sealed with — see
    /// [`seal_with_tag_size`](Self::seal_with_tag_size)).
    pub async fn open_with_tag_size(
        &self,
        nonce: impl Into<Cow<'_, [u8]>>,
        aad: impl Into<Cow<'_, [u8]>>,
        tag_size: u8,
        ciphertext: impl Into<DataSource<'_>>,
    ) -> Result<StreamReader<u8>, Error> {
        let (nonce, aad) = (nonce.into().into_owned(), aad.into().into_owned());
        run_sourced(ciphertext.into(), |rx| {
            self.0.open(nonce, aad, Some(tag_size), rx)
        })
        .await
    }

    /// The name of the key's algorithm family, e.g. `"AES-GCM"` —
    /// WebCrypto's `KeyAlgorithm.name`, spelled as the [W3C Web Cryptography
    /// API algorithm registry](https://www.w3.org/TR/WebCryptoAPI/#algorithm-overview)
    /// spells it.
    pub fn algorithm_name(&self) -> String {
        self.0.algorithm_name()
    }

    /// The key length in bits, e.g. `256` for AES-256-GCM (WebCrypto's
    /// `AesKeyAlgorithm.length`).
    pub fn algorithm_length(&self) -> u32 {
        self.0.algorithm_length()
    }

    /// The algorithm's standard nonce size in bytes, e.g. `12` for AES-GCM
    /// — always accepted by [`seal`](Self::seal)/[`open`](Self::open).
    /// Whether other lengths are accepted is the algorithm's contract
    /// (AES-GCM accepts any non-empty nonce; the ChaCha constructions
    /// accept exactly this size).
    pub fn nonce_size(&self) -> u32 {
        self.0.nonce_size()
    }

    /// The size in bytes of the tag trailing the ciphertext, e.g. `16` —
    /// for framing arithmetic (sealed length = plaintext length +
    /// `tag_size`).
    pub fn tag_size(&self) -> u32 {
        self.0.tag_size()
    }

    /// Whether [`export_key_raw`](Self::export_key_raw) may return the key material
    /// (see [`Mac::extractable`]).
    pub fn extractable(&self) -> bool {
        self.0.extractable()
    }

    /// Whether the key permits [`seal`](Self::seal) — the usage recorded
    /// at mint. A refused operation fails [`Error::NotPermitted`].
    pub fn can_seal(&self) -> bool {
        self.0.can_seal()
    }

    /// Whether the key permits [`open`](Self::open). See
    /// [`can_seal`](Self::can_seal).
    pub fn can_open(&self) -> bool {
        self.0.can_open()
    }

    /// Whether the key may wrap keys — recorded and enforced ahead of
    /// operations (the package has no wrap operation yet).
    pub fn can_wrap(&self) -> bool {
        self.0.can_wrap()
    }

    /// Whether the key may unwrap keys. See [`can_wrap`](Self::can_wrap).
    pub fn can_unwrap(&self) -> bool {
        self.0.can_unwrap()
    }

    /// The raw key material; fails with [`Error::NotExtractable`] unless the
    /// key was minted extractable (an API property, not a physical one —
    /// see [`Mac::export_key_raw`]).
    pub async fn export_key_raw(&self) -> Result<Vec<u8>, Error> {
        self.0.export_key_raw().await.map_err(Error::from)
    }

    /// The key as an RFC 7517 `oct` JSON Web Key (JSON text), behind the
    /// same extractability gate as [`export_key_raw`](Self::export_key_raw).
    /// Algorithms with no registered JWK form (the XChaCha
    /// constructions) fail [`Error::Unsupported`].
    pub async fn export_key_jwk(&self) -> Result<String, Error> {
        self.0.export_key_jwk().await.map_err(Error::from)
    }
}

/// An `aead-internal-nonce.internal-nonce-key`: misuse-resistant
/// authenticated encryption — the nonce is implementation-managed and
/// carried in the sealed message (wire format per the minting interface),
/// so nonce reuse is unrepresentable rather than merely discouraged.
pub struct AeadInternalNonce(bindings::aead_internal_nonce::InternalNonceKey);
newtype_common!(
    AeadInternalNonce,
    bindings::aead_internal_nonce::InternalNonceKey,
    "internal-nonce-key"
);

impl AeadInternalNonce {
    /// Encrypt and authenticate `plaintext` under a fresh
    /// implementation-generated nonce with `aad`, yielding the
    /// self-contained sealed message.
    ///
    /// Returns a [`Seal`], which starts the operation when awaited — so a
    /// `Seal` dropped unused draws nothing from this key's nonce budget.
    ///
    /// Fails with [`Error::KeyExhausted`] once the implementation can no
    /// longer guarantee nonce uniqueness for this key — mint a fresh key to
    /// continue sealing.
    pub fn seal<'a>(
        &'a self,
        aad: impl Into<Cow<'a, [u8]>>,
        plaintext: impl Into<DataSource<'a>>,
    ) -> Seal<'a> {
        let aad = aad.into().into_owned();
        Seal::new(
            plaintext.into(),
            Box::new(move |rx| Box::pin(self.0.seal(aad, rx))),
        )
    }

    /// Decrypt and verify a sealed message (as produced by
    /// [`seal`](Self::seal)) under `aad`.
    ///
    /// The stream is handed back only after the whole input is consumed and
    /// the tag verified: `Ok` *is* the authentication statement, and
    /// unverified plaintext is never observable. Any failure — a bad tag,
    /// wrong associated data, or input too short to carry the wire format —
    /// fails closed with [`Error::AuthenticationFailed`], with no detail.
    pub async fn open(
        &self,
        aad: impl Into<Cow<'_, [u8]>>,
        sealed: impl Into<DataSource<'_>>,
    ) -> Result<StreamReader<u8>, Error> {
        let aad = aad.into().into_owned();
        run_sourced(sealed.into(), |rx| self.0.open(aad, rx)).await
    }

    /// The name of the key's algorithm family, e.g. `"AES-GCM"` — spelled as
    /// the [W3C Web Cryptography API algorithm
    /// registry](https://www.w3.org/TR/WebCryptoAPI/#algorithm-overview)
    /// spells it.
    pub fn algorithm_name(&self) -> String {
        self.0.algorithm_name()
    }

    /// The key length in bits, e.g. `256`.
    pub fn algorithm_length(&self) -> u32 {
        self.0.algorithm_length()
    }

    /// The remaining nonce budget, as a key-rotation hint; `None` when no
    /// budget is enforced. Monotonically non-increasing, and `Some(0)` means
    /// the next [`seal`](Self::seal) fails [`Error::KeyExhausted`] — but not
    /// an exact invocation count (implementations may decrement faster than
    /// one per seal).
    pub fn seals_remaining(&self) -> Option<u64> {
        self.0.seals_remaining()
    }

    /// Whether [`export_key_raw`](Self::export_key_raw) may return the key material
    /// (see [`Mac::extractable`]).
    pub fn extractable(&self) -> bool {
        self.0.extractable()
    }

    /// Whether the key permits [`seal`](Self::seal) — the usage recorded
    /// at mint. A refused operation fails [`Error::NotPermitted`].
    pub fn can_seal(&self) -> bool {
        self.0.can_seal()
    }

    /// Whether the key permits [`open`](Self::open). See
    /// [`can_seal`](Self::can_seal).
    pub fn can_open(&self) -> bool {
        self.0.can_open()
    }

    /// The raw key material; fails with [`Error::NotExtractable`] unless the
    /// key was minted extractable (an API property, not a physical one —
    /// see [`Mac::export_key_raw`]). The nonce budget does not travel with the
    /// material.
    pub async fn export_key_raw(&self) -> Result<Vec<u8>, Error> {
        self.0.export_key_raw().await.map_err(Error::from)
    }
}

/// A `digest.digest`: a reusable, algorithm-bound hash.
///
/// A digest authenticates nothing by itself: to check untrusted data
/// against a known digest, compare [`compute`](Self::compute)'s result with
/// [`constant_time_equal`]; when authenticity is needed, use a [`Mac`].
pub struct Digest(bindings::digest::Digest);
newtype_common!(Digest, bindings::digest::Digest, "digest");

impl Digest {
    /// Digest `data`. The resource is reusable; the result is
    /// chunking-invariant.
    pub async fn compute(&self, data: impl Into<DataSource<'_>>) -> Result<Vec<u8>, Error> {
        run_sourced(data.into(), |rx| self.0.compute(rx)).await
    }

    /// The name of the algorithm this resource is bound to, e.g.
    /// `"SHA-256"` — spelled as the [W3C Web Cryptography API algorithm
    /// registry](https://www.w3.org/TR/WebCryptoAPI/#algorithm-overview)
    /// (and `crypto.subtle.digest`) spells it.
    pub fn algorithm_name(&self) -> String {
        self.0.algorithm_name()
    }
}

/// A `signature.verifying-key`: public-key signature verification.
/// Secret-free — a component holding only this key provably cannot sign.
pub struct VerifyingKey(bindings::signature::VerifyingKey);
newtype_common!(
    VerifyingKey,
    bindings::signature::VerifyingKey,
    "verifying-key"
);

impl VerifyingKey {
    /// Verify `sig` over `data`.
    ///
    /// Fails closed with [`Error::AuthenticationFailed`] if the signature
    /// does not verify — deliberately a `Result` rather than a `bool`: an
    /// ignored boolean fails open, a dropped `Result` does not. The precise
    /// verification criterion (which degenerate keys and signatures must be
    /// rejected) is defined by the key's minting interface, exactly like
    /// the wire format.
    pub async fn verify(
        &self,
        data: impl Into<DataSource<'_>>,
        sig: impl Into<Cow<'_, [u8]>>,
    ) -> Result<(), Error> {
        let sig = sig.into().into_owned();
        run_sourced(data.into(), |rx| self.0.verify(rx, sig)).await
    }

    /// The name of the key's algorithm family, e.g. `"Ed25519"` or
    /// `"ECDSA"` — WebCrypto's `KeyAlgorithm.name`, spelled as the [W3C Web
    /// Cryptography API algorithm
    /// registry](https://www.w3.org/TR/WebCryptoAPI/#algorithm-overview)
    /// spells it.
    pub fn algorithm_name(&self) -> String {
        self.0.algorithm_name()
    }

    /// The registry name of the curve for curve-parameterized algorithms,
    /// e.g. `"P-256"` (WebCrypto's `EcKeyAlgorithm.namedCurve`). `None` for
    /// Ed25519, whose curve is implied by the name.
    pub fn algorithm_curve(&self) -> Option<String> {
        self.0.algorithm_curve()
    }

    /// The registry name of the digest bound at mint, e.g. `"SHA-256"`.
    /// `None` for Ed25519: RFC 8032 fixes SHA-512 internally, so it is not
    /// a parameter.
    pub fn algorithm_hash(&self) -> Option<String> {
        self.0.algorithm_hash()
    }

    /// The public key material, in the minting interface's documented
    /// public format.
    ///
    /// There is no extractability gate on this key, so this never fails
    /// with [`Error::NotExtractable`]. It can still fail with
    /// [`Error::Other`]: a provider may hold the key as a handle it can
    /// *use* but not *read*, so verifying succeeds while recovering the
    /// encoding does not.
    pub async fn export_key_raw(&self) -> Result<Vec<u8>, Error> {
        self.0.export_key_raw().await.map_err(Error::from)
    }
}

/// A `signature.signing-key`: private-key signing.
pub struct SigningKey(bindings::signature::SigningKey);
newtype_common!(SigningKey, bindings::signature::SigningKey, "signing-key");

impl SigningKey {
    /// Sign `data`, returning the signature in the minting interface's
    /// documented wire format.
    ///
    /// Fails only for operational reasons ([`Error::Other`], or
    /// [`Error::Read`] for a failing `DataSource::from_reader` source) —
    /// never for misuse, which is unrepresentable.
    pub async fn sign(&self, data: impl Into<DataSource<'_>>) -> Result<Vec<u8>, Error> {
        run_sourced(data.into(), |rx| self.0.sign(rx)).await
    }

    /// See [`VerifyingKey::algorithm_name`].
    pub fn algorithm_name(&self) -> String {
        self.0.algorithm_name()
    }

    /// See [`VerifyingKey::algorithm_curve`].
    pub fn algorithm_curve(&self) -> Option<String> {
        self.0.algorithm_curve()
    }

    /// See [`VerifyingKey::algorithm_hash`].
    pub fn algorithm_hash(&self) -> Option<String> {
        self.0.algorithm_hash()
    }

    /// Whether the private key material may be exported. There is
    /// currently no export operation — extractability is mint-time
    /// recorded policy that future format-specific exports and
    /// platform-backed key storage honor (see the WIT
    /// `signing-key.extractable` doc).
    pub fn extractable(&self) -> bool {
        self.0.extractable()
    }

    /// Whether the key permits [`sign`](Self::sign) — the usage recorded
    /// at mint (or carried by a platform keystore key). A refused
    /// operation fails [`Error::NotPermitted`].
    pub fn can_sign(&self) -> bool {
        self.0.can_sign()
    }
}

// --- key & digest creation -------------------------------------------------------

/// An unauthenticated-cipher key (AES-CBC or AES-CTR), minted by
/// [`aes_cbc`] / [`aes_ctr`]. **Nothing this key does authenticates**:
/// ciphertext is malleable and a successful [`decrypt`](Self::decrypt) is
/// not evidence the input is untampered. Default to [`Aead`]; use this
/// kind only where an existing format fixes the mode. See the WIT
/// `cipher` interface for the full contract.
pub struct CipherKey(bindings::cipher::CipherKey);
newtype_common!(CipherKey, bindings::cipher::CipherKey, "cipher-key");

impl CipherKey {
    /// Encrypt `plaintext` under `iv` (for AES-CTR, the initial counter
    /// block plus the counter width in bits; AES-CBC callers pass `None`).
    /// The caller owns the IV discipline — see the minting interface's
    /// Security notes.
    pub fn encrypt<'a>(
        &'a self,
        iv: impl Into<Cow<'a, [u8]>>,
        counter_length: Option<u8>,
        plaintext: impl Into<DataSource<'a>>,
    ) -> Seal<'a> {
        let iv = iv.into().into_owned();
        Seal::new(
            plaintext.into(),
            Box::new(move |rx| Box::pin(self.0.encrypt(iv, counter_length, rx))),
        )
    }

    /// Decrypt `ciphertext` under `iv`. The plaintext is unauthenticated:
    /// treat it as attacker-influenced data even on success. Malformed
    /// input fails [`Error::Other`], deliberately uniform across
    /// conditions.
    pub async fn decrypt(
        &self,
        iv: impl Into<Cow<'_, [u8]>>,
        counter_length: Option<u8>,
        ciphertext: impl Into<DataSource<'_>>,
    ) -> Result<StreamReader<u8>, Error> {
        let iv = iv.into().into_owned();
        run_sourced(ciphertext.into(), |rx| {
            self.0.decrypt(iv, counter_length, rx)
        })
        .await
    }

    /// The name of the key's algorithm family, e.g. `"AES-CBC"`.
    pub fn algorithm_name(&self) -> String {
        self.0.algorithm_name()
    }

    /// The key length in bits.
    pub fn algorithm_length(&self) -> u32 {
        self.0.algorithm_length()
    }

    /// The algorithm's IV size in bytes (`16` for the AES modes).
    pub fn iv_size(&self) -> u32 {
        self.0.iv_size()
    }

    /// Whether [`export_key_raw`](Self::export_key_raw) may return the key
    /// material (see [`Mac::extractable`]).
    pub fn extractable(&self) -> bool {
        self.0.extractable()
    }

    /// Whether the key permits [`encrypt`](Self::encrypt).
    pub fn can_encrypt(&self) -> bool {
        self.0.can_encrypt()
    }

    /// Whether the key permits [`decrypt`](Self::decrypt).
    pub fn can_decrypt(&self) -> bool {
        self.0.can_decrypt()
    }

    /// Whether the key may wrap keys — recorded ahead of operations.
    pub fn can_wrap(&self) -> bool {
        self.0.can_wrap()
    }

    /// Whether the key may unwrap keys. See [`can_wrap`](Self::can_wrap).
    pub fn can_unwrap(&self) -> bool {
        self.0.can_unwrap()
    }

    /// The raw key material, behind the extractability gate.
    pub async fn export_key_raw(&self) -> Result<Vec<u8>, Error> {
        Ok(self.0.export_key_raw().await?)
    }

    /// The key as an `oct` JWK, behind the same gate.
    pub async fn export_key_jwk(&self) -> Result<String, Error> {
        Ok(self.0.export_key_jwk().await?)
    }
}

// --- derivation ------------------------------------------------------------------

/// An `hkdf.ikm`: imported input keying material for HKDF, minted by
/// [`hkdf::import_ikm`]. Never readable back through the API under any
/// grant; the grants recorded at import are copied onto every
/// [`DeriveInput`] built on it (via [`hkdf_sha2::prepare`] and friends).
pub struct Ikm(bindings::hkdf::Ikm);
newtype_common!(Ikm, bindings::hkdf::Ikm, "ikm");

impl Ikm {
    /// Whether inputs built on this material may yield raw bits. See
    /// [`DeriveOptions::derive_bits`].
    pub fn can_derive_bits(&self) -> bool {
        self.0.can_derive_bits()
    }

    /// Whether inputs built on this material may mint keys. See
    /// [`DeriveOptions::derive_key`].
    pub fn can_derive_key(&self) -> bool {
        self.0.can_derive_key()
    }
}

/// A `pbkdf2.password`: an imported password, minted by
/// [`pbkdf2::import_password`]. Never readable back through the API under
/// any grant; the grants recorded at import are copied onto every
/// [`DeriveInput`] built on it (via [`pbkdf2_sha2::prepare`] and friends).
pub struct Password(bindings::pbkdf2::Password);
newtype_common!(Password, bindings::pbkdf2::Password, "password");

impl Password {
    /// Whether inputs built on this password may yield raw bits. See
    /// [`DeriveOptions::derive_bits`].
    pub fn can_derive_bits(&self) -> bool {
        self.0.can_derive_bits()
    }

    /// Whether inputs built on this password may mint keys. See
    /// [`DeriveOptions::derive_key`].
    pub fn can_derive_key(&self) -> bool {
        self.0.can_derive_key()
    }
}

/// A `derivation.derive-input`: a fully parameterized derivation — base
/// secret plus every parameter, minted by the `prepare` functions
/// ([`hkdf_sha2::prepare`], [`pbkdf2_sha2::prepare`], …) and by
/// [`AgreementSecretKey::agree`].
///
/// Consume it through [`derive_bits`](Self::derive_bits) or hand it to a
/// target interface's `derive_key` (e.g. [`hmac_sha2::derive_key`],
/// [`aes_gcm::derive_key`]); both may run any number of times. While an
/// input is live it may hold derivation state of its own (for HKDF, the
/// PRK), so a base secret's sensitivity extends to the inputs built on it.
pub struct DeriveInput(bindings::derivation::DeriveInput);
newtype_common!(
    DeriveInput,
    bindings::derivation::DeriveInput,
    "derive-input"
);

impl DeriveInput {
    /// The derived bits.
    ///
    /// `length` is in bits — WebCrypto's denomination for this parameter —
    /// and must be a multiple of 8 (none of the package's implementations
    /// serve sub-byte outputs). `None` means the source's natural output
    /// length: an agreement's full shared secret (32 bytes for X25519).
    /// KDF sources have none — their output length is a caller choice —
    /// so `None` fails [`Error::Other`] there, matching the platform's
    /// own null-length behavior.
    ///
    /// Fails [`Error::NotPermitted`] without the
    /// [`derive_bits`](DeriveOptions::derive_bits) grant.
    pub async fn derive_bits(&self, length: Option<u32>) -> Result<Vec<u8>, Error> {
        self.0.derive_bits(length).await.map_err(Error::from)
    }

    /// Whether [`derive_bits`](Self::derive_bits) (and minting
    /// *extractable* keys) is permitted — the grant copied from the base
    /// secret. A refused operation fails [`Error::NotPermitted`].
    pub fn can_derive_bits(&self) -> bool {
        self.0.can_derive_bits()
    }

    /// Whether the target interfaces' `derive_key` is permitted. See
    /// [`can_derive_bits`](Self::can_derive_bits).
    pub fn can_derive_key(&self) -> bool {
        self.0.can_derive_key()
    }
}

/// A `key-agreement.public-key`: the exchangeable half of an agreement
/// keypair, minted by [`x25519`]'s imports and
/// [`generate_key`](x25519::generate_key). Secret-free.
pub struct AgreementPublicKey(bindings::key_agreement::PublicKey);
newtype_common!(
    AgreementPublicKey,
    bindings::key_agreement::PublicKey,
    "public-key"
);

impl AgreementPublicKey {
    /// The name of the key's algorithm family, e.g. `"X25519"` —
    /// WebCrypto's `KeyAlgorithm.name`.
    pub fn algorithm_name(&self) -> String {
        self.0.algorithm_name()
    }

    /// The public key material, in the minting interface's documented
    /// public format (32 bytes for X25519).
    ///
    /// There is no extractability gate on public material, so this never
    /// fails [`Error::NotExtractable`] — but it can fail [`Error::Other`]:
    /// a provider may hold the key as a handle it can use but not read
    /// (see [`VerifyingKey::export_key_raw`]).
    pub async fn export_key_raw(&self) -> Result<Vec<u8>, Error> {
        self.0.export_key_raw().await.map_err(Error::from)
    }

    /// The public key as a JWK (an RFC 8037 OKP public key for X25519),
    /// with the same handle-not-bytes fallibility as
    /// [`export_key_raw`](Self::export_key_raw).
    pub async fn export_key_jwk(&self) -> Result<String, Error> {
        self.0.export_key_jwk().await.map_err(Error::from)
    }

    /// The public key as an X.509 SubjectPublicKeyInfo (DER), with the
    /// same handle-not-bytes fallibility as
    /// [`export_key_raw`](Self::export_key_raw).
    pub async fn export_key_spki(&self) -> Result<Vec<u8>, Error> {
        self.0.export_key_spki().await.map_err(Error::from)
    }
}

/// A `key-agreement.secret-key`: the private half of an agreement keypair.
/// [`agree`](Self::agree) is one-shot on the immutable key; the derivation
/// state lives in the [`DeriveInput`] it returns.
pub struct AgreementSecretKey(bindings::key_agreement::SecretKey);
newtype_common!(
    AgreementSecretKey,
    bindings::key_agreement::SecretKey,
    "secret-key"
);

impl AgreementSecretKey {
    /// The shared secret with `peer`, as a [`DeriveInput`] whose grants
    /// are copied from this key's mint options.
    ///
    /// The returned input has a *natural* output length — the agreement's
    /// full shared secret — so `derive_bits(None)` returns the whole
    /// secret and [`hkdf_sha2::prepare_from`] accepts it as IKM.
    ///
    /// Fails [`Error::InvalidKey`] if the shared secret is the all-zero
    /// value (a small-order `peer`; the mandatory contributory check,
    /// performed in constant time) or if `peer` is bound to a different
    /// algorithm than this key.
    pub async fn agree(&self, peer: &AgreementPublicKey) -> Result<DeriveInput, Error> {
        Ok(DeriveInput::from_raw(self.0.agree(&peer.0).await?))
    }

    /// See [`AgreementPublicKey::algorithm_name`].
    pub fn algorithm_name(&self) -> String {
        self.0.algorithm_name()
    }

    /// Whether inputs agreed by this key may yield raw bits. See
    /// [`DeriveOptions::derive_bits`].
    pub fn can_derive_bits(&self) -> bool {
        self.0.can_derive_bits()
    }

    /// Whether inputs agreed by this key may mint keys. See
    /// [`DeriveOptions::derive_key`].
    pub fn can_derive_key(&self) -> bool {
        self.0.can_derive_key()
    }

    /// Whether the export functions may return this key's material (see
    /// [`Mac::extractable`]).
    pub fn extractable(&self) -> bool {
        self.0.extractable()
    }

    /// The secret key as a JWK (an RFC 8037 OKP private key for X25519);
    /// fails [`Error::NotExtractable`] unless the key was minted
    /// extractable.
    pub async fn export_key_jwk(&self) -> Result<String, Error> {
        self.0.export_key_jwk().await.map_err(Error::from)
    }

    /// The secret key as a PKCS#8 PrivateKeyInfo (DER), behind the same
    /// extractability gate as [`export_key_jwk`](Self::export_key_jwk).
    pub async fn export_key_pkcs8(&self) -> Result<Vec<u8>, Error> {
        self.0.export_key_pkcs8().await.map_err(Error::from)
    }
}

pub mod aes_cbc;
pub mod aes_ctr;
pub mod aes_gcm;
pub mod aes_gcm_internal_nonce;
#[cfg(feature = "chacha")]
pub mod chacha20_poly1305;
pub mod ecdsa;
pub mod ed25519;
pub mod hkdf;
pub mod hkdf_sha1;
pub mod hkdf_sha2;
pub mod hmac_sha1;
pub mod hmac_sha2;
pub mod pbkdf2;
pub mod pbkdf2_sha1;
pub mod pbkdf2_sha2;
pub mod sha1_checked;
pub mod sha2;
pub mod x25519;
#[cfg(feature = "chacha")]
pub mod xchacha20_poly1305;
#[cfg(feature = "chacha")]
pub mod xchacha20_poly1305_internal_nonce;

/// `bytes.constant-time-equal`: whether `a` and `b` are equal, in time
/// independent of their *contents* (necessarily dependent on their
/// lengths). Use this to compare a computed digest or tag against an
/// untrusted expected value without creating a timing oracle.
///
/// Deliberately a component import rather than an in-guest comparison: the
/// provider — a native host, for the wasmtime and jco implementations —
/// performs the comparison, where constant-time properties actually hold,
/// whereas code compiled *inside* a wasm module keeps them only best-effort
/// through the engine's own compilation.
pub fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    bindings::bytes::constant_time_equal(a, b)
}

#[cfg(test)]
mod tests {
    use super::{Error, Feed};

    fn read_error() -> Error {
        Error::Read(std::io::Error::other("reader failed"))
    }

    /// Rejection maps to [`Error::ShortWrite`] only through the
    /// success-path requirement; completion satisfies it. (The rest of
    /// the precedence is statement order at the join sites: the feed's
    /// `?` — always a read failure — before the operation's, before this
    /// requirement.)
    #[test]
    fn rejection_is_short_write_only_by_requirement() {
        assert!(matches!(
            Feed::Rejected.require_complete(),
            Err(Error::ShortWrite)
        ));
        assert!(Feed::Complete.require_complete().is_ok());
    }

    /// Every WIT error case maps onto its own variant — and the match in
    /// `From` is exhaustive, so a case added to the WIT is a compile error
    /// here rather than a silent fallthrough.
    #[test]
    fn wit_errors_map_onto_their_variants() {
        use super::bindings::types::{Error as Raw, ExtensionError};
        assert!(matches!(
            Error::from(Raw::InvalidKey("k".into())),
            Error::InvalidKey(_)
        ));
        assert!(matches!(
            Error::from(Raw::InvalidNonce("n".into())),
            Error::InvalidNonce(_)
        ));
        assert!(matches!(
            Error::from(Raw::AuthenticationFailed),
            Error::AuthenticationFailed
        ));
        assert!(matches!(
            Error::from(Raw::NotExtractable),
            Error::NotExtractable
        ));
        assert!(matches!(
            Error::from(Raw::Unsupported("u".into())),
            Error::Unsupported(_)
        ));
        assert!(matches!(
            Error::from(Raw::NotPermitted("p".into())),
            Error::NotPermitted(_)
        ));
        assert!(matches!(
            Error::from(Raw::KeyExhausted),
            Error::KeyExhausted
        ));
        assert!(matches!(
            Error::from(Raw::Other("o".into())),
            Error::Other(_)
        ));
        assert!(matches!(
            Error::from(Raw::Extension(ExtensionError {
                origin: "lann:webcrypto".into(),
                name: "collision-detected".into(),
                message: "m".into(),
            })),
            Error::Extension(_)
        ));
    }

    /// Every `Display` rendering identifies its condition: the WIT-mirrored
    /// variants by case name, the SDK-local ones by prose.
    #[test]
    fn display_identifies_every_condition() {
        let renders = [
            (Error::InvalidKey("k".into()), "invalid-key: k"),
            (Error::InvalidNonce("n".into()), "invalid-nonce: n"),
            (Error::AuthenticationFailed, "authentication-failed"),
            (Error::NotExtractable, "not-extractable"),
            (Error::Unsupported("u".into()), "unsupported: u"),
            (Error::NotPermitted("p".into()), "not-permitted: p"),
            (Error::KeyExhausted, "key-exhausted"),
            (Error::Other("o".into()), "other: o"),
        ];
        for (error, expected) in renders {
            assert_eq!(error.to_string(), expected);
        }
        assert!(read_error().to_string().contains("reader failed"));
        assert!(Error::ShortWrite.to_string().starts_with("short write"));
    }
}
