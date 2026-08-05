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
/// Ids are compared verbatim — the amended component-model label grammar
/// (number-only kebab words after the first) admits the incumbent's RSA
/// modulus words (`…-sha256-2048`) directly.
fn census() -> Inventory {
    parse_fixture(include_str!("census-fixture.lock"))
}

/// The post-cutover census: every case under `plan::POST_CUTOVER_ROWS`,
/// same line format as the incumbent fixture. Unlike that fixture this
/// one *grows*: regenerate with
/// `cargo test -p conformance-guest-ct regen_post_cutover_census -- --ignored`
/// and commit the diff — the diff is the review surface, like a
/// lockfile's (#302: the component-test lock pins generated rows at
/// prefix granularity only, so this fixture is the per-case bound).
fn post_cutover_census() -> Inventory {
    parse_fixture(include_str!("census-postcutover.lock"))
}

fn parse_fixture(text: &str) -> Inventory {
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

/// Expand generator rows into an inventory (asserting each case's own
/// features equal the row's tags — tags live at the row).
fn expand_rows(rows: &[plan::Row]) -> Inventory {
    let mut out = Inventory::new();
    for row in rows {
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
    out
}

/// Expand the port's cutover-frozen inventory: every `plan::ROWS`
/// generator row plus the probe table.
fn ported() -> Inventory {
    let mut out = expand_rows(plan::ROWS);
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
    assert_eq!(census.len(), 16427, "census size changed under us");
}

/// Post-cutover rows: exact per-case parity with the growing fixture
/// (the per-case bound the component-test lockfile's prefix-granular
/// `[[generated]]` entries do not provide — #302).
#[test]
fn post_cutover_inventory_matches_its_fixture() {
    let fixture = post_cutover_census();
    let expanded = expand_rows(plan::POST_CUTOVER_ROWS);

    let missing: Vec<_> = fixture
        .keys()
        .filter(|k| !expanded.contains_key(*k))
        .collect();
    let extra: Vec<_> = expanded
        .keys()
        .filter(|k| !fixture.contains_key(*k))
        .collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "post-cutover inventory drift: {} fixture cases gone (first: {:?}), {} cases not in the \
         fixture (first: {:?}) — if the change is intentional, regenerate with `cargo test -p \
         conformance-guest-ct regen_post_cutover_census -- --ignored` and commit the diff",
        missing.len(),
        missing.first(),
        extra.len(),
        extra.first(),
    );
    for (name, features) in &fixture {
        assert_eq!(
            &expanded[name], features,
            "feature tags for {name} diverge from the post-cutover fixture"
        );
    }
}

/// Every generated prefix the built suite actually registers (the
/// committed lockfile's `[[generated]]` entries, drift-checked against
/// the artifact by `lock-check`) is pinned by exactly one census
/// fixture: `ROWS` (frozen, incumbent fixture) or `POST_CUTOVER_ROWS`
/// (growing fixture). A new `#[case_row]` prefix added without a
/// fixture home fails here.
#[test]
fn every_locked_generated_prefix_has_a_census_fixture() {
    let lock = include_str!("../tests.lock");
    let locked: std::collections::BTreeSet<&str> = lock
        .lines()
        .filter_map(|l| l.trim().strip_prefix("prefix = \""))
        .map(|l| l.split('"').next().unwrap())
        .collect();
    assert!(
        !locked.is_empty(),
        "no [[generated]] prefixes parsed from tests.lock"
    );
    let pinned: std::collections::BTreeSet<&str> = plan::ROWS
        .iter()
        .chain(plan::POST_CUTOVER_ROWS)
        .map(|r| r.prefix)
        .collect();
    let unpinned: Vec<_> = locked.difference(&pinned).collect();
    assert!(
        unpinned.is_empty(),
        "locked generated prefixes with no census fixture (add to plan::POST_CUTOVER_ROWS and \
         regenerate census-postcutover.lock): {unpinned:?}"
    );
    let overlap: Vec<_> = plan::ROWS
        .iter()
        .map(|r| r.prefix)
        .filter(|p| plan::POST_CUTOVER_ROWS.iter().any(|q| q.prefix == *p))
        .collect();
    assert!(overlap.is_empty(), "rows in both tables: {overlap:?}");
}

/// Regenerates `census-postcutover.lock` from `POST_CUTOVER_ROWS`.
/// Deliberately `#[ignore]`d: run it on purpose, review the diff.
#[test]
#[ignore = "fixture regeneration: run explicitly and commit the diff"]
fn regen_post_cutover_census() {
    let expanded = expand_rows(plan::POST_CUTOVER_ROWS);
    let mut out = String::from(
        "# Post-cutover census: every case under plan::POST_CUTOVER_ROWS, in the\n\
         # incumbent fixture's line format. Generated by regen_post_cutover_census\n\
         # (census_test.rs); regenerate on any post-cutover row change and commit\n\
         # the diff - the diff is the review surface.\n",
    );
    for (name, features) in &expanded {
        if features.is_empty() {
            out.push_str(&format!("{{ name = \"{name}\" }}\n"));
        } else {
            let feats = features
                .iter()
                .map(|f| format!("\"{f}\""))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("{{ name = \"{name}\", features = [{feats}] }}\n"));
        }
    }
    std::fs::write(
        concat!(env!("CARGO_MANIFEST_DIR"), "/src/census-postcutover.lock"),
        out,
    )
    .unwrap();
}
