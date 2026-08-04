//! Native census-parity test: the port's static inventory must equal the
//! incumbent census (`conformance/signing-guest/tests.lock`) exactly.
//! The incumbent census carries no feature tags, so there are no
//! additive decline cases to exclude.

use std::collections::BTreeMap;

type Inventory = BTreeMap<String, Vec<String>>;

/// Parse the incumbent census: `{ name = "..." }` (no features in this
/// suite — asserted below).
fn census() -> Inventory {
    let text = include_str!("../../signing-guest/tests.lock");
    let mut out = Inventory::new();
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("{ name = \"") else {
            continue;
        };
        let (name, rest) = rest.split_once('"').expect("closing quote");
        let features = match rest.split_once("features = [") {
            Some((_, feats)) => {
                let feats = feats.split(']').next().unwrap();
                feats
                    .split(',')
                    .map(|f| f.trim().trim_matches('"').to_string())
                    .filter(|f| !f.is_empty())
                    .collect()
            }
            None => Vec::new(),
        };
        assert!(
            out.insert(name.to_string(), features).is_none(),
            "duplicate census entry {name}"
        );
    }
    out
}

/// The port's inventory: the probe table (the `#[case]` fns in `lib.rs`
/// are one-per-row lookups into it by ident, so the table is the
/// authoritative name source).
fn ported() -> Inventory {
    let mut out = Inventory::new();
    for probe in crate::probes::PROBES {
        assert!(
            out.insert(
                probe.case_id(),
                probe.features.iter().map(|s| s.to_string()).collect()
            )
            .is_none(),
            "probe {} collides",
            probe.case_id()
        );
    }
    out
}

#[test]
fn inventory_matches_the_incumbent_census() {
    let census = census();
    let ported = ported();

    let missing: Vec<_> = census.keys().filter(|k| !ported.contains_key(*k)).collect();
    let extra: Vec<_> = ported.keys().filter(|k| !census.contains_key(*k)).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "inventory drift: {} census cases unported (first: {:?}), {} cases not in census (first: {:?})",
        missing.len(),
        missing.first(),
        extra.len(),
        extra.first(),
    );
    for (name, features) in &census {
        assert_eq!(
            &ported[name], features,
            "feature tags for {name} diverge from the census"
        );
        assert!(
            features.is_empty(),
            "census grew a feature tag on {name}; the port needs a !feature decline case"
        );
    }
    assert_eq!(census.len(), 8, "census size changed under us");
}
