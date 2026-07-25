//! `conformance-runner`: classifies per-target conformance results against
//! `conformance/manifests.toml` and renders `conformance/matrix.md`.
//!
//! Usage: `conformance-runner --manifests <toml> --results <dir> --matrix-out <md>`.
//!
//! Every `<dir>/*.json` results file (as written by the adapters) is read and
//! each test classified: **pass**, **fail**, **expected-fail** (failed and
//! matched by the target's `expected-fail` list), or **unexpected-pass**
//! (passed but matched — treated as an error so stale manifest entries get
//! pruned). Targets present in the manifests but missing a results file are
//! warned about, not failed. Exits nonzero iff any fail or unexpected-pass
//! exists across the results present.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::Context as _;

#[derive(serde::Deserialize)]
struct Manifests {
    targets: BTreeMap<String, TargetManifest>,
}

#[derive(serde::Deserialize)]
struct TargetManifest {
    #[serde(rename = "expected-fail", default)]
    expected_fail: Vec<String>,
}

#[derive(serde::Deserialize)]
struct ResultsFile {
    target: String,
    results: Vec<TestResult>,
}

#[derive(serde::Deserialize)]
struct TestResult {
    id: String,
    passed: bool,
    #[serde(default)]
    detail: String,
}

/// The classification of one test result against the target's manifest.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Pass,
    Fail,
    ExpectedFail,
    UnexpectedPass,
}

/// One classified result.
struct Classified {
    target: String,
    id: String,
    detail: String,
    class: Class,
}

/// Whether a manifest entry (an exact id, or a prefix ending in `*`) matches
/// a test id.
fn entry_matches(entry: &str, id: &str) -> bool {
    match entry.strip_suffix('*') {
        Some(prefix) => id.starts_with(prefix),
        None => entry == id,
    }
}

/// The suite group a test id belongs to: `probe`, or its first two
/// path segments (e.g. `aes-gcm/wycheproof`).
fn group_of(id: &str) -> String {
    if let Some(rest) = id.split_once('/') {
        if rest.0 == "probe" {
            return "probe".to_string();
        }
        if let Some((second, _)) = rest.1.split_once('/') {
            return format!("{}/{}", rest.0, second);
        }
        return format!("{}/{}", rest.0, rest.1);
    }
    id.to_string()
}

/// Flatten a detail string for one-line markdown rendering, truncating long
/// tails.
fn render_detail(detail: &str) -> String {
    let mut flat = detail.replace('\n', "; ");
    const MAX: usize = 200;
    if flat.len() > MAX {
        let mut end = MAX;
        while !flat.is_char_boundary(end) {
            end -= 1;
        }
        flat.truncate(end);
        flat.push('…');
    }
    flat
}

fn parse_args() -> anyhow::Result<(PathBuf, PathBuf, PathBuf)> {
    let mut manifests = None;
    let mut results = None;
    let mut matrix_out = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--manifests" => {
                manifests = Some(PathBuf::from(
                    args.next().context("--manifests needs a value")?,
                ))
            }
            "--results" => {
                results = Some(PathBuf::from(
                    args.next().context("--results needs a value")?,
                ))
            }
            "--matrix-out" => {
                matrix_out = Some(PathBuf::from(
                    args.next().context("--matrix-out needs a value")?,
                ))
            }
            other => anyhow::bail!("unknown argument {other:?}"),
        }
    }
    Ok((
        manifests.context("--manifests <toml> is required")?,
        results.context("--results <dir> is required")?,
        matrix_out.context("--matrix-out <md> is required")?,
    ))
}

fn main() -> anyhow::Result<()> {
    let (manifests_path, results_dir, matrix_path) = parse_args()?;

    let manifests: Manifests = toml::from_str(
        &std::fs::read_to_string(&manifests_path)
            .with_context(|| format!("reading {}", manifests_path.display()))?,
    )
    .with_context(|| format!("parsing {}", manifests_path.display()))?;

    // Read every results file in the directory.
    let mut result_files: Vec<ResultsFile> = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(&results_dir)
        .with_context(|| format!("reading {}", results_dir.display()))?
        .collect::<Result<_, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        let file: ResultsFile = serde_json::from_str(
            &std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?,
        )
        .with_context(|| format!("parsing {}", path.display()))?;
        result_files.push(file);
    }

    // Classify every result against its target's manifest.
    let empty: Vec<String> = Vec::new();
    let mut classified: Vec<Classified> = Vec::new();
    for file in &result_files {
        let expected_fail = manifests
            .targets
            .get(&file.target)
            .map(|t| &t.expected_fail)
            .unwrap_or(&empty);
        for result in &file.results {
            let matched = expected_fail
                .iter()
                .any(|entry| entry_matches(entry, &result.id));
            let class = match (result.passed, matched) {
                (true, false) => Class::Pass,
                (true, true) => Class::UnexpectedPass,
                (false, true) => Class::ExpectedFail,
                (false, false) => Class::Fail,
            };
            classified.push(Classified {
                target: file.target.clone(),
                id: result.id.clone(),
                detail: result.detail.clone(),
                class,
            });
        }
    }

    // Targets: manifest order (alphabetical) first, then any result-only ones.
    let mut targets: Vec<String> = manifests.targets.keys().cloned().collect();
    for file in &result_files {
        if !targets.contains(&file.target) {
            targets.push(file.target.clone());
        }
    }
    let targets_with_results: BTreeSet<&str> =
        result_files.iter().map(|f| f.target.as_str()).collect();
    let missing: Vec<&String> = manifests
        .targets
        .keys()
        .filter(|t| !targets_with_results.contains(t.as_str()))
        .collect();

    let groups: BTreeSet<String> = classified.iter().map(|c| group_of(&c.id)).collect();

    // --- render the matrix ---------------------------------------------------

    let mut md = String::new();
    md.push_str("# Conformance matrix\n\n");
    md.push_str(
        "Generated by `conformance-runner` from `conformance/results/*.json` \
         against `conformance/manifests.toml`. Cells are `passed/total` per \
         suite group (`+N xfail` counts expected failures).\n\n",
    );

    md.push_str("| Suite |");
    for target in &targets {
        md.push_str(&format!(" {target} |"));
    }
    md.push('\n');
    md.push_str("| --- |");
    for _ in &targets {
        md.push_str(" --- |");
    }
    md.push('\n');
    for group in &groups {
        md.push_str(&format!("| {group} |"));
        for target in &targets {
            let in_cell: Vec<&Classified> = classified
                .iter()
                .filter(|c| &c.target == target && group_of(&c.id) == *group)
                .collect();
            if in_cell.is_empty() {
                md.push_str(" — |");
                continue;
            }
            let total = in_cell.len();
            let passed = in_cell.iter().filter(|c| c.class == Class::Pass).count();
            let xfail = in_cell
                .iter()
                .filter(|c| c.class == Class::ExpectedFail)
                .count();
            let mut cell = format!("{passed}/{total}");
            if xfail > 0 {
                cell.push_str(&format!(" +{xfail} xfail"));
            }
            md.push_str(&format!(" {cell} |"));
        }
        md.push('\n');
    }
    md.push('\n');

    let fails: Vec<&Classified> = classified
        .iter()
        .filter(|c| c.class == Class::Fail)
        .collect();
    let unexpected: Vec<&Classified> = classified
        .iter()
        .filter(|c| c.class == Class::UnexpectedPass)
        .collect();
    let xfails: Vec<&Classified> = classified
        .iter()
        .filter(|c| c.class == Class::ExpectedFail)
        .collect();

    md.push_str("## Failures and unexpected passes\n\n");
    if fails.is_empty() && unexpected.is_empty() {
        md.push_str("None.\n");
    } else {
        for c in &fails {
            md.push_str(&format!(
                "- FAIL `{}` `{}`: {}\n",
                c.target,
                c.id,
                render_detail(&c.detail)
            ));
        }
        for c in &unexpected {
            md.push_str(&format!(
                "- UNEXPECTED-PASS `{}` `{}`: passed but listed in expected-fail\n",
                c.target, c.id
            ));
        }
    }
    md.push('\n');

    md.push_str("## Expected failures\n\n");
    if xfails.is_empty() {
        md.push_str("None.\n");
    } else {
        for c in &xfails {
            md.push_str(&format!(
                "- XFAIL `{}` `{}`: {}\n",
                c.target,
                c.id,
                render_detail(&c.detail)
            ));
        }
    }
    md.push('\n');

    md.push_str("## Targets without results\n\n");
    if missing.is_empty() {
        md.push_str("None.\n");
    } else {
        for target in &missing {
            md.push_str(&format!(
                "- `{target}`: in manifests but no results file (warning only)\n"
            ));
        }
    }

    if let Some(parent) = matrix_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&matrix_path, &md)
        .with_context(|| format!("writing {}", matrix_path.display()))?;

    for target in &missing {
        eprintln!(
            "warning: target {target} has no results file in {}",
            results_dir.display()
        );
    }
    println!(
        "conformance: {} results across {} target(s): {} fail, {} unexpected-pass, {} xfail -> {}",
        classified.len(),
        targets_with_results.len(),
        fails.len(),
        unexpected.len(),
        xfails.len(),
        matrix_path.display()
    );

    if !fails.is_empty() || !unexpected.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}
