//! Smoke tests: build the HPKE guest component and run it under the
//! Wasmtime host (`lann-webcrypto-wasmtime` serving the `lann:webcrypto`
//! imports). Round trips plus the RFC 9180 A.1/A.2 base-mode known answers
//! — deliberately a smoke suite, not a conformance suite.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use hpke_host_test::{derive_key_pair, generate_key_pair, open, seal, seal_deterministic, AeadId};

/// Build the guest component once per test-binary run, through the
/// experiment's `just build-component` (the single definition of that
/// build), and return its path.
fn component() -> &'static Path {
    static COMPONENT: OnceLock<PathBuf> = OnceLock::new();
    COMPONENT.get_or_init(|| {
        let experiment_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let output = Command::new("just")
            .arg("build-component")
            .current_dir(&experiment_root)
            .output()
            .expect("failed to spawn just");
        assert!(
            output.status.success(),
            "just build-component failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        experiment_root.join("build/hpke.component.wasm")
    })
}

fn unhex(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

async fn round_trip(aead: AeadId) {
    let component = component();
    let info = b"experiments:hpke smoke";
    let aad = b"smoke aad";
    let plaintext = b"Beauty is truth, truth beauty";

    let pair = generate_key_pair(component)
        .await
        .expect("host/guest failure")
        .expect("generate-key-pair failed");
    assert_eq!(pair.public_key.len(), 32);
    assert_eq!(pair.secret_key.len(), 32);

    let sealed = seal(component, aead, &pair.public_key, info, aad, plaintext)
        .await
        .expect("host/guest failure")
        .expect("seal failed");
    assert_eq!(sealed.enc.len(), 32);
    assert_eq!(sealed.ciphertext.len(), plaintext.len() + 16);

    let opened = open(
        component,
        aead,
        &pair.secret_key,
        &sealed.enc,
        info,
        aad,
        &sealed.ciphertext,
    )
    .await
    .expect("host/guest failure")
    .expect("open failed");
    assert_eq!(opened, plaintext);

    // A flipped ciphertext bit must not open.
    let mut tampered = sealed.ciphertext.clone();
    tampered[0] ^= 0x80;
    open(
        component,
        aead,
        &pair.secret_key,
        &sealed.enc,
        info,
        aad,
        &tampered,
    )
    .await
    .expect("host/guest failure")
    .expect_err("tampered ciphertext opened");

    // The wrong AAD must not open.
    open(
        component,
        aead,
        &pair.secret_key,
        &sealed.enc,
        info,
        b"wrong aad",
        &sealed.ciphertext,
    )
    .await
    .expect("host/guest failure")
    .expect_err("wrong aad opened");

    // The wrong recipient key must not open.
    let other = generate_key_pair(component)
        .await
        .expect("host/guest failure")
        .expect("generate-key-pair failed");
    open(
        component,
        aead,
        &other.secret_key,
        &sealed.enc,
        info,
        aad,
        &sealed.ciphertext,
    )
    .await
    .expect("host/guest failure")
    .expect_err("wrong recipient key opened");
}

#[tokio::test(flavor = "multi_thread")]
async fn round_trip_aes_128_gcm() {
    round_trip(AeadId::Aes128Gcm).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn round_trip_aes_256_gcm() {
    round_trip(AeadId::Aes256Gcm).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn round_trip_chacha20_poly1305() {
    round_trip(AeadId::Chacha20Poly1305).await;
}

/// One RFC 9180 base-mode test vector: DeriveKeyPair known answers for
/// both parties, deterministic single-shot seal (ephemeral from `ikmE`)
/// against the vector's `enc` and first ciphertext, and open.
struct Rfc9180Vector {
    aead: AeadId,
    ikm_e: &'static str,
    pk_em: &'static str,
    sk_em: &'static str,
    ikm_r: &'static str,
    pk_rm: &'static str,
    sk_rm: &'static str,
    ct: &'static str,
}

/// Shared by every A.* vector: info "Ode on a Grecian Urn", plaintext
/// "Beauty is truth, truth beauty", aad "Count-0" (sequence number 0).
const INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
const PT: &str = "4265617574792069732074727574682c20747275746820626561757479";
const AAD: &str = "436f756e742d30";

async fn known_answer(vector: Rfc9180Vector) {
    let component = component();

    let receiver = derive_key_pair(component, &unhex(vector.ikm_r))
        .await
        .expect("host/guest failure")
        .expect("derive-key-pair(ikmR) failed");
    assert_eq!(receiver.secret_key, unhex(vector.sk_rm), "skRm");
    assert_eq!(receiver.public_key, unhex(vector.pk_rm), "pkRm");

    let ephemeral = derive_key_pair(component, &unhex(vector.ikm_e))
        .await
        .expect("host/guest failure")
        .expect("derive-key-pair(ikmE) failed");
    assert_eq!(ephemeral.secret_key, unhex(vector.sk_em), "skEm");
    assert_eq!(ephemeral.public_key, unhex(vector.pk_em), "pkEm");

    let sealed = seal_deterministic(
        component,
        vector.aead,
        &unhex(vector.pk_rm),
        &unhex(vector.ikm_e),
        &unhex(INFO),
        &unhex(AAD),
        &unhex(PT),
    )
    .await
    .expect("host/guest failure")
    .expect("seal-deterministic failed");
    assert_eq!(sealed.enc, unhex(vector.pk_em), "enc");
    assert_eq!(sealed.ciphertext, unhex(vector.ct), "ct");

    let opened = open(
        component,
        vector.aead,
        &unhex(vector.sk_rm),
        &sealed.enc,
        &unhex(INFO),
        &unhex(AAD),
        &sealed.ciphertext,
    )
    .await
    .expect("host/guest failure")
    .expect("open failed");
    assert_eq!(opened, unhex(PT), "pt");
}

/// RFC 9180 A.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
#[tokio::test(flavor = "multi_thread")]
async fn rfc9180_a1_base() {
    known_answer(Rfc9180Vector {
        aead: AeadId::Aes128Gcm,
        ikm_e: "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234",
        pk_em: "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
        sk_em: "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
        ikm_r: "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037",
        pk_rm: "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
        sk_rm: "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
        ct: "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9\
             6d8770ac83d07bea87e13c512a",
    })
    .await;
}

/// RFC 9180 A.2: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
/// ChaCha20-Poly1305.
#[tokio::test(flavor = "multi_thread")]
async fn rfc9180_a2_base() {
    known_answer(Rfc9180Vector {
        aead: AeadId::Chacha20Poly1305,
        ikm_e: "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b",
        pk_em: "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
        sk_em: "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
        ikm_r: "1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df",
        pk_rm: "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
        sk_rm: "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
        ct: "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db\
             21993c62ce81883d2dd1b51a28",
    })
    .await;
}
