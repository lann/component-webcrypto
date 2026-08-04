//! Native census-parity test: the port's static inventory must equal the
//! incumbent census (`src/census-fixture.lock` — the incumbent
//! `conformance-guest`'s final `tests.lock`, byte-frozen at the M1.6
//! cutover; the incumbent itself is deleted) exactly — the
//! decline cases are additive and deliberately excluded here (they are
//! new; the lockfile-diff script accounts for them).

use std::collections::BTreeMap;

use crate::plan;

type Inventory = BTreeMap<String, Vec<String>>;

/// Parse the incumbent census: `{ name = "...", features = [...] }`.
fn census() -> Inventory {
    let text = include_str!("census-fixture.lock");
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

/// Expand the port's inventory: every generator row (asserting each
/// case's own features equal the row's tags — tags live at the row) plus
/// the probe table.
fn ported() -> Inventory {
    let mut out = Inventory::new();
    for row in plan::ROWS {
        let cases = plan::cases_under(row.prefix);
        assert!(
            !cases.is_empty(),
            "generator row {} matches no cases",
            row.prefix
        );
        for case in cases {
            assert_eq!(
                case.features, row.tags,
                "case {} disagrees with its row's tags ({})",
                case.id, row.prefix
            );
            assert!(
                out.insert(
                    case.id.clone(),
                    case.features.iter().map(|s| s.to_string()).collect()
                )
                .is_none(),
                "case {} produced by more than one row",
                case.id
            );
        }
    }
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
    }
    assert_eq!(census.len(), 11578, "census size changed under us");
}
