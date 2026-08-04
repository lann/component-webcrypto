//! The CLI driver component for the fully in-guest HPKE smoke run.
//!
//! It imports the HPKE guest's exported `experiments:hpke/hpke` interface
//! and exports an async `wasi:cli/run`, so the composed component — HPKE
//! guest + `lann-webcrypto-guest-provider` provider + this driver — runs under a plain
//! `wasmtime run -S cli`. It drives a seal/open round trip (with tamper and
//! wrong-AAD failure checks) per AEAD and reports on stdout/stderr.

mod bindings {
    wit_bindgen::generate!({
        path: "../guest/wit",
        inline: "
            package experiments:hpke-driver;
            world driver {
                import experiments:hpke/hpke@0.1.0;
            }
        ",
        generate_all,
    });
}

use bindings::experiments::hpke::hpke;

async fn round_trip(aead: hpke::AeadId) -> Result<(), String> {
    let pair = hpke::generate_key_pair().await?;
    let info = b"experiments:hpke composed smoke".to_vec();
    let aad = b"composed aad".to_vec();
    let plaintext = b"Beauty is truth, truth beauty".to_vec();

    let sealed = hpke::seal(
        aead,
        pair.public_key.clone(),
        info.clone(),
        aad.clone(),
        plaintext.clone(),
    )
    .await?;
    let opened = hpke::open(
        aead,
        pair.secret_key.clone(),
        sealed.enc.clone(),
        info.clone(),
        aad.clone(),
        sealed.ciphertext.clone(),
    )
    .await?;
    if opened != plaintext {
        return Err("round trip produced different plaintext".into());
    }

    let mut tampered = sealed.ciphertext.clone();
    tampered[0] ^= 0x80;
    if hpke::open(
        aead,
        pair.secret_key.clone(),
        sealed.enc.clone(),
        info.clone(),
        aad.clone(),
        tampered,
    )
    .await
    .is_ok()
    {
        return Err("tampered ciphertext opened".into());
    }
    if hpke::open(
        aead,
        pair.secret_key.clone(),
        sealed.enc.clone(),
        info.clone(),
        b"wrong aad".to_vec(),
        sealed.ciphertext.clone(),
    )
    .await
    .is_ok()
    {
        return Err("wrong aad opened".into());
    }
    Ok(())
}

async fn smoke() -> Result<(), String> {
    for (name, aead) in [
        ("aes-128-gcm", hpke::AeadId::Aes128Gcm),
        ("aes-256-gcm", hpke::AeadId::Aes256Gcm),
    ] {
        round_trip(aead).await.map_err(|e| format!("{name}: {e}"))?;
        println!("{name}: round trip, tamper, and wrong-aad checks passed");
    }
    Ok(())
}

struct Component;

impl wasip3::exports::cli::run::Guest for Component {
    async fn run() -> Result<(), ()> {
        match smoke().await {
            Ok(()) => {
                println!("OK: hpke composed smoke passed.");
                Ok(())
            }
            Err(err) => {
                eprintln!("hpke composed smoke failed: {err}");
                Err(())
            }
        }
    }
}

wasip3::cli::command::export!(Component);
