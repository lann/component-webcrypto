//! `conformance-runner`: the aggregator for the cross-target conformance
//! results. Expectation policy lives in the cases (self-describing)
//! and target facts in `conformance/targets.toml`; this program only checks
//! that the mail arrived intact, gates on failures, and renders
//! `conformance/matrix.md`. See `--help` for the flags.
//!
//! Transport invariants, each an error (exit nonzero):
//! - every non-`optional` target produced a results file for each suite it
//!   runs — derived: every suite except those whose `requires` names a
//!   feature the target is missing (an `optional` target's missing file is
//!   a warning, and results for an excluded suite are an error);
//! - at most one results file per (target, suite), with no duplicate case
//!   names inside it;
//! - each results file's case names and feature tags exactly match its
//!   suite's checked-in lockfile (suite changes land intentionally via
//!   `just conformance::update-lock`);
//! - each results file's declared `missing` features match the target's
//!   entry in targets.toml (adapters and the manifest cannot drift apart);
//! - no case reports `fail`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::Context as _;
use clap::Parser;
use conformance_report::{CaseResult, Outcome, ResultsFile};
use indexmap::IndexMap;

#[derive(serde::Deserialize)]
struct Targets {
    suites: BTreeMap<String, Suite>,
    targets: BTreeMap<String, Target>,
    /// The classification of every declarable feature name (see
    /// targets.toml's header and `wit/README.md`, "Portability contract").
    #[serde(default)]
    features: BTreeMap<String, Feature>,
}

#[derive(serde::Deserialize)]
struct Feature {
    kind: FeatureKind,
}

#[derive(serde::Deserialize, PartialEq, Eq, Clone, Copy, Debug)]
#[serde(rename_all = "lowercase")]
enum FeatureKind {
    /// `@unstable` in the WIT: the consumer opt-in for capability that
    /// cannot be uniform.
    Gated,
    /// A whole interface a world withholds; absence fails at `wac plug`
    /// time.
    Structural,
}

#[derive(serde::Deserialize)]
struct Suite {
    /// Features the suite needs structurally (its guest's world imports
    /// them): a target missing one cannot run this suite at all.
    #[serde(default)]
    requires: Vec<String>,
}

#[derive(serde::Deserialize)]
struct Target {
    #[serde(rename = "missing-features")]
    missing_features: Vec<String>,
    #[serde(default)]
    optional: bool,
}

impl Target {
    /// Whether this target runs `suite`: it does unless the suite requires
    /// a feature the target is missing.
    fn runs(&self, suite: &Suite) -> bool {
        suite
            .requires
            .iter()
            .all(|feature| !self.missing_features.contains(feature))
    }
}

/// One suite lockfile: case name -> feature tags, in suite order (the
/// canonical case order the results viewer renders).
#[derive(Debug)]
struct Lock {
    cases: IndexMap<String, Vec<String>>,
}

/// Parse a lockfile (TOML: a `cases` array of `{ name, features? }` inline
/// tables, as written by `just conformance::update-lock`).
fn parse_lock(text: &str) -> anyhow::Result<Lock> {
    let mut cases = IndexMap::new();
    for case in conformance_report::parse_lock(text)? {
        if cases.insert(case.name.clone(), case.features).is_some() {
            anyhow::bail!("duplicate case {:?}", case.name);
        }
    }
    Ok(Lock { cases })
}

/// The group a case name belongs to: `probe`, or its first two path
/// segments — algorithm and vector source (e.g. `aes-gcm/wycheproof`).
fn group_of(name: &str) -> String {
    if let Some(rest) = name.split_once('/') {
        if rest.0 == "probe" {
            return "probe".to_string();
        }
        if let Some((second, _)) = rest.1.split_once('/') {
            return format!("{}/{}", rest.0, second);
        }
        return format!("{}/{}", rest.0, rest.1);
    }
    name.to_string()
}

/// Validate the manifest's own declarations against the portability
/// contract (`wit/README.md`, "Portability contract"): every feature a
/// target declares missing, every feature a suite requires, and every
/// feature tag a lockfile carries must be classified in the `[features]`
/// table. An unclassified name is a typo or an ungated runtime
/// divergence, and the policy forbids declaring the latter — it is a
/// defect to resolve, not a fact to record (AGENTS.md, "Portability:
/// divergence is resolved, not accumulated").
fn validate_declarations(
    targets: &Targets,
    locks: &BTreeMap<String, Lock>,
    problems: &mut Vec<String>,
) {
    for (name, target) in &targets.targets {
        for feature in &target.missing_features {
            if !targets.features.contains_key(feature) {
                problems.push(format!(
                    "target {name}: missing-features entry {feature:?} is not classified in \
                     [features] — only gated or structural features may be declared missing"
                ));
            }
        }
    }
    for (name, suite) in &targets.suites {
        for feature in &suite.requires {
            match targets.features.get(feature) {
                None => problems.push(format!(
                    "suite {name}: requires {feature:?}, which is not classified in [features]"
                )),
                Some(f) if f.kind != FeatureKind::Structural => problems.push(format!(
                    "suite {name}: requires {feature:?}, which is classified {:?} — `requires` \
                     expresses a world-level (structural) need",
                    f.kind
                )),
                Some(_) => {}
            }
        }
    }
    for (suite, lock) in locks {
        for (case, tags) in &lock.cases {
            for tag in tags {
                if !targets.features.contains_key(tag) {
                    problems.push(format!(
                        "suite {suite}: case {case:?} is tagged {tag:?}, which is not classified \
                         in [features]"
                    ));
                }
            }
        }
    }
}

/// Validate one results file against the target table and its suite lock,
/// appending human-readable problems to `problems`.
fn validate_file(
    file: &ResultsFile,
    targets: &Targets,
    locks: &BTreeMap<String, Lock>,
    problems: &mut Vec<String>,
) {
    let at = format!("{}/{}", file.target, file.suite);

    match targets.targets.get(&file.target) {
        None => problems.push(format!("{at}: target not declared in targets.toml")),
        Some(target) => {
            let declared: BTreeSet<&str> =
                target.missing_features.iter().map(String::as_str).collect();
            let reported: BTreeSet<&str> =
                file.missing_features.iter().map(String::as_str).collect();
            if declared != reported {
                problems.push(format!(
                    "{at}: adapter declared missing-features {reported:?}, but targets.toml \
                     declares {declared:?}"
                ));
            }
            if let Some(suite) = targets.suites.get(&file.suite) {
                if !target.runs(suite) {
                    problems.push(format!(
                        "{at}: results for a suite this target's missing-features exclude \
                         (it requires {:?})",
                        suite.requires
                    ));
                }
            }
        }
    }

    if !targets.suites.contains_key(&file.suite) {
        problems.push(format!(
            "{at}: suite {:?} is not declared in targets.toml",
            file.suite
        ));
    }
    let Some(lock) = locks.get(&file.suite) else {
        problems.push(format!(
            "{at}: no lockfile for suite {:?} (pass --lock {}=<path>)",
            file.suite, file.suite
        ));
        return;
    };

    let mut seen = BTreeSet::new();
    for case in &file.results {
        if !seen.insert(case.name.as_str()) {
            problems.push(format!("{at}: duplicate case {:?}", case.name));
            continue;
        }
        match lock.cases.get(&case.name) {
            None => problems.push(format!(
                "{at}: case {:?} is not in the suite lockfile (run `just \
                 conformance::update-lock` if the suite changed intentionally)",
                case.name
            )),
            Some(tags) if *tags != case.features => problems.push(format!(
                "{at}: case {:?} reports feature tags {:?}, but the lockfile has {:?} (run \
                 `just conformance::update-lock` if the suite changed intentionally)",
                case.name, case.features, tags
            )),
            Some(_) => {}
        }
        if case.outcome == Outcome::Unknown {
            problems.push(format!(
                "{at}: case {:?} reports an outcome that is not pass/fail/skipped",
                case.name
            ));
        }
    }
    for name in lock.cases.keys() {
        if !seen.contains(name.as_str()) {
            problems.push(format!(
                "{at}: case {name:?} is in the suite lockfile but produced no result (run \
                 `just conformance::update-lock` if the suite changed intentionally)"
            ));
        }
    }
}

/// Check every declared (target, suite) pair produced exactly one results
/// file, appending problems (or warnings for `optional` targets).
fn check_presence(
    targets: &Targets,
    files: &[ResultsFile],
    problems: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    let mut seen: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for file in files {
        *seen
            .entry((file.target.as_str(), file.suite.as_str()))
            .or_default() += 1;
    }
    for (pair, count) in &seen {
        if *count > 1 {
            problems.push(format!(
                "{}/{}: {count} results files for one (target, suite) pair",
                pair.0, pair.1
            ));
        }
    }
    for (name, target) in &targets.targets {
        for (suite_name, suite) in &targets.suites {
            if !target.runs(suite) {
                continue;
            }
            if !seen.contains_key(&(name.as_str(), suite_name.as_str())) {
                let message = format!("{name}/{suite_name}: no results file");
                if target.optional {
                    warnings.push(format!("{message} (target is optional)"));
                } else {
                    problems.push(message);
                }
            }
        }
    }
}

/// Render the cross-target matrix.
fn render_matrix(targets: &Targets, files: &[ResultsFile]) -> String {
    // Targets: manifest order first, then any result-only ones.
    let mut target_names: Vec<String> = targets.targets.keys().cloned().collect();
    for file in files {
        if !target_names.contains(&file.target) {
            target_names.push(file.target.clone());
        }
    }
    let groups: BTreeSet<String> = files
        .iter()
        .flat_map(|f| f.results.iter().map(|c| group_of(&c.name)))
        .collect();

    let mut md = String::new();
    md.push_str("# Conformance matrix\n\n");
    md.push_str(
        "Generated by `conformance-runner` from `conformance/results/*.json` against \
         `conformance/targets.toml` and the suite lockfiles. Cells are `passed/total` \
         per group; `-N` counts cases skipped because the target declares a \
         feature missing (see targets.toml).\n\n",
    );

    md.push_str("| Group |");
    for target in &target_names {
        md.push_str(&format!(" {target} |"));
    }
    md.push_str("\n| --- |");
    for _ in &target_names {
        md.push_str(" --- |");
    }
    md.push('\n');
    for group in &groups {
        md.push_str(&format!("| {group} |"));
        for target in &target_names {
            let in_cell: Vec<&CaseResult> = files
                .iter()
                .filter(|f| &f.target == target)
                .flat_map(|f| f.results.iter())
                .filter(|c| group_of(&c.name) == *group)
                .collect();
            if in_cell.is_empty() {
                md.push_str(" — |");
                continue;
            }
            let total = in_cell.len();
            let passed = in_cell
                .iter()
                .filter(|c| c.outcome == Outcome::Pass)
                .count();
            let skipped = in_cell
                .iter()
                .filter(|c| c.outcome == Outcome::Skipped)
                .count();
            let mut cell = format!("{passed}/{total}");
            if skipped > 0 {
                cell.push_str(&format!(" -{skipped} skipped"));
            }
            md.push_str(&format!(" {cell} |"));
        }
        md.push('\n');
    }
    md.push('\n');

    md.push_str("## Failures\n\n");
    let mut any_failures = false;
    for file in files {
        for case in &file.results {
            if case.outcome == Outcome::Fail {
                any_failures = true;
                let mut detail = case.detail.replace('\n', "; ");
                const MAX: usize = 200;
                if detail.len() > MAX {
                    let mut end = MAX;
                    while !detail.is_char_boundary(end) {
                        end -= 1;
                    }
                    detail.truncate(end);
                    detail.push('…');
                }
                md.push_str(&format!(
                    "- FAIL `{}` `{}`: {detail}\n",
                    file.target, case.name
                ));
            }
        }
    }
    if !any_failures {
        md.push_str("None.\n");
    }
    md.push('\n');

    md.push_str("## Skips\n\n");
    md.push_str(
        "Cases whose feature the target declares missing (grouped; the feature-tagged \
         probes assert the correct decline).\n\n",
    );
    let mut any_skips = false;
    for file in files {
        let mut by_group: BTreeMap<String, (usize, &str)> = BTreeMap::new();
        for case in &file.results {
            if case.outcome == Outcome::Skipped {
                let entry = by_group
                    .entry(group_of(&case.name))
                    .or_insert((0, case.detail.as_str()));
                entry.0 += 1;
            }
        }
        for (group, (count, detail)) in by_group {
            any_skips = true;
            md.push_str(&format!(
                "- `{}` `{group}`: {count} skipped — {detail}\n",
                file.target
            ));
        }
    }
    if !any_skips {
        md.push_str("None.\n");
    }
    md
}

/// Render the machine-readable aggregate the results viewer
/// (`conformance/web/`) consumes: the declared targets and suites, every
/// lockfile case in suite order, and per-target outcome columns aligned to
/// that case order (compact codes: `p`/`f`/`s`; `null` where the (target,
/// suite) pair produced no results). Details ride a sparse side map (case
/// index -> detail) for fail/skip outcomes only, keeping the file small.
fn render_json(
    targets: &Targets,
    locks: &BTreeMap<String, Lock>,
    files: &[ResultsFile],
) -> anyhow::Result<String> {
    #[derive(serde::Serialize)]
    struct ViewerTarget<'a> {
        #[serde(rename = "missing-features")]
        missing_features: &'a [String],
        optional: bool,
    }
    #[derive(serde::Serialize)]
    struct ViewerSuite<'a> {
        requires: &'a [String],
    }
    #[derive(serde::Serialize)]
    struct ViewerCase<'a> {
        name: &'a str,
        suite: &'a str,
        #[serde(skip_serializing_if = "<[String]>::is_empty")]
        features: &'a [String],
    }
    #[derive(serde::Serialize)]
    struct ViewerData<'a> {
        targets: BTreeMap<&'a str, ViewerTarget<'a>>,
        suites: BTreeMap<&'a str, ViewerSuite<'a>>,
        cases: Vec<ViewerCase<'a>>,
        outcomes: BTreeMap<&'a str, Vec<Option<&'static str>>>,
        details: BTreeMap<&'a str, BTreeMap<String, &'a str>>,
    }

    let mut cases = Vec::new();
    for (suite, lock) in locks {
        for (name, features) in &lock.cases {
            cases.push(ViewerCase {
                name,
                suite,
                features,
            });
        }
    }

    let mut outcomes = BTreeMap::new();
    let mut details = BTreeMap::new();
    for name in targets.targets.keys() {
        let by_suite: BTreeMap<&str, BTreeMap<&str, &CaseResult>> = files
            .iter()
            .filter(|f| &f.target == name)
            .map(|f| {
                let by_name = f.results.iter().map(|c| (c.name.as_str(), c)).collect();
                (f.suite.as_str(), by_name)
            })
            .collect();
        let mut column = Vec::with_capacity(cases.len());
        let mut target_details = BTreeMap::new();
        // The column is driven by the same `cases` list the viewer renders,
        // so outcome indexes cannot misalign with it.
        for case in &cases {
            let result = by_suite
                .get(case.suite)
                .and_then(|m| m.get(case.name))
                .copied();
            let code = match result.map(|c| c.outcome) {
                Some(Outcome::Pass) => Some("p"),
                Some(Outcome::Fail) => Some("f"),
                Some(Outcome::Skipped) => Some("s"),
                // Absent (or unknown-outcome, which validation already
                // flags) renders as "no result".
                _ => None,
            };
            if let Some(c) = result {
                if matches!(c.outcome, Outcome::Fail | Outcome::Skipped) && !c.detail.is_empty() {
                    target_details.insert(column.len().to_string(), c.detail.as_str());
                }
            }
            column.push(code);
        }
        outcomes.insert(name.as_str(), column);
        details.insert(name.as_str(), target_details);
    }

    let data = ViewerData {
        targets: targets
            .targets
            .iter()
            .map(|(name, t)| {
                (
                    name.as_str(),
                    ViewerTarget {
                        missing_features: &t.missing_features,
                        optional: t.optional,
                    },
                )
            })
            .collect(),
        suites: targets
            .suites
            .iter()
            .map(|(name, suite)| {
                (
                    name.as_str(),
                    ViewerSuite {
                        requires: &suite.requires,
                    },
                )
            })
            .collect(),
        cases,
        outcomes,
        details,
    };
    Ok(serde_json::to_string(&data)?)
}

#[derive(Parser)]
#[command(
    about = "Aggregates per-target conformance results against targets.toml and the suite \
             lockfiles; renders the matrix and the results-viewer data."
)]
struct Args {
    /// The target- and suite-facts manifest (targets.toml).
    #[arg(long)]
    targets: PathBuf,
    /// The directory holding the per-target results files.
    #[arg(long)]
    results: PathBuf,
    /// Where to write the rendered matrix.
    #[arg(long)]
    matrix_out: PathBuf,
    /// Where to write the results-viewer aggregate, if requested.
    #[arg(long)]
    json_out: Option<PathBuf>,
    /// A suite lockfile to validate against, as <suite>=<path>; repeatable.
    #[arg(long = "lock", value_name = "SUITE=PATH", value_parser = parse_lock_flag)]
    locks: Vec<(String, PathBuf)>,
}

/// Split a `--lock` value into its suite name and lockfile path.
fn parse_lock_flag(value: &str) -> Result<(String, PathBuf), String> {
    let (suite, path) = value
        .split_once('=')
        .ok_or_else(|| "expected <suite>=<path>".to_string())?;
    Ok((suite.to_string(), PathBuf::from(path)))
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let targets: Targets = toml::from_str(
        &std::fs::read_to_string(&args.targets)
            .with_context(|| format!("reading {}", args.targets.display()))?,
    )
    .with_context(|| format!("parsing {}", args.targets.display()))?;

    let mut locks = BTreeMap::new();
    for (suite, path) in &args.locks {
        let lock = parse_lock(
            &std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?,
        )
        .with_context(|| format!("parsing {}", path.display()))?;
        locks.insert(suite.clone(), lock);
    }

    // Read every results file in the directory.
    let mut files: Vec<ResultsFile> = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(&args.results)
        .with_context(|| format!("reading {}", args.results.display()))?
        .collect::<Result<_, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        // The viewer aggregate may live in the results directory (the
        // justfile puts it there so the per-run cleaning covers it); it is
        // this program's own output, not a results file.
        if Some(path.as_path()) == args.json_out.as_deref() {
            continue;
        }
        let file: ResultsFile = serde_json::from_str(
            &std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?,
        )
        .with_context(|| format!("parsing {}", path.display()))?;
        files.push(file);
    }

    let mut problems = Vec::new();
    let mut warnings = Vec::new();
    check_presence(&targets, &files, &mut problems, &mut warnings);
    validate_declarations(&targets, &locks, &mut problems);
    for file in &files {
        validate_file(file, &targets, &locks, &mut problems);
    }
    let failures: usize = files
        .iter()
        .flat_map(|f| f.results.iter())
        .filter(|c| c.outcome == Outcome::Fail)
        .count();
    let total: usize = files.iter().map(|f| f.results.len()).sum();
    let skipped: usize = files
        .iter()
        .flat_map(|f| f.results.iter())
        .filter(|c| c.outcome == Outcome::Skipped)
        .count();

    let md = render_matrix(&targets, &files);
    if let Some(parent) = args.matrix_out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&args.matrix_out, &md)
        .with_context(|| format!("writing {}", args.matrix_out.display()))?;

    if let Some(json_path) = &args.json_out {
        let json = render_json(&targets, &locks, &files)?;
        if let Some(parent) = json_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(json_path, &json)
            .with_context(|| format!("writing {}", json_path.display()))?;
    }

    for warning in &warnings {
        eprintln!("warning: {warning}");
    }
    for problem in &problems {
        eprintln!("error: {problem}");
    }
    println!(
        "conformance: {total} results across {} file(s): {failures} failed, {skipped} \
         skipped, {} transport problem(s) -> {}",
        files.len(),
        problems.len(),
        args.matrix_out.display()
    );

    if failures > 0 || !problems.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets() -> Targets {
        toml::from_str(
            r#"
            [features.sha1-checked]
            kind = "gated"

            [features.ecdsa-sign]
            kind = "structural"

            [suites.shared]

            [suites.signing]
            requires = ["ecdsa-sign"]

            [targets.native]
            missing-features = []

            [targets.composed-like]
            missing-features = ["ecdsa-sign"]

            [targets.web]
            missing-features = ["sha1-checked"]
            optional = true
            "#,
        )
        .unwrap()
    }

    fn lock() -> Lock {
        parse_lock(
            r#"
            # comment
            cases = [
                { name = "alg/src/tc1/whole" },
                { name = "alg/src/tc2/whole", features = ["sha1-checked"] },
                { name = "probe/check" },
            ]
            "#,
        )
        .unwrap()
    }

    fn file(target: &str, suite: &str, results: Vec<CaseResult>) -> ResultsFile {
        let missing_features = match target {
            "web" => vec!["sha1-checked".to_string()],
            "composed-like" => vec!["ecdsa-sign".to_string()],
            _ => Vec::new(),
        };
        ResultsFile {
            target: target.to_string(),
            suite: suite.to_string(),
            missing_features,
            results,
        }
    }

    fn case(name: &str, features: &[&str], outcome: Outcome) -> CaseResult {
        CaseResult {
            name: name.to_string(),
            features: features.iter().map(|s| s.to_string()).collect(),
            outcome,
            detail: String::new(),
        }
    }

    fn full_results() -> Vec<CaseResult> {
        vec![
            case("alg/src/tc1/whole", &[], Outcome::Pass),
            case("alg/src/tc2/whole", &["sha1-checked"], Outcome::Pass),
            case("probe/check", &[], Outcome::Pass),
        ]
    }

    fn validate(file: &ResultsFile) -> Vec<String> {
        let mut problems = Vec::new();
        let locks = BTreeMap::from([("shared".to_string(), lock())]);
        validate_file(file, &targets(), &locks, &mut problems);
        problems
    }

    fn declaration_problems(manifest: &str, lock_text: &str) -> Vec<String> {
        let targets: Targets = toml::from_str(manifest).unwrap();
        let locks = BTreeMap::from([("shared".to_string(), parse_lock(lock_text).unwrap())]);
        let mut problems = Vec::new();
        validate_declarations(&targets, &locks, &mut problems);
        problems
    }

    /// The classified manifest passes the declaration check whole.
    #[test]
    fn classified_declarations_pass() {
        let locks = BTreeMap::from([("shared".to_string(), lock())]);
        let mut problems = Vec::new();
        validate_declarations(&targets(), &locks, &mut problems);
        assert_eq!(problems, Vec::<String>::new());
    }

    /// A missing-features entry with no [features] classification is
    /// refused: an ungated runtime divergence may not be declared.
    #[test]
    fn unclassified_missing_feature_is_refused() {
        let problems = declaration_problems(
            r#"
            [suites.shared]
            [targets.native]
            missing-features = ["some-quirk"]
            "#,
            r#"cases = [{ name = "probe/check" }]"#,
        );
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("\"some-quirk\" is not classified"));
    }

    /// A suite `requires` must name a structural feature: gated features
    /// are declined at runtime, not linked out of a world.
    #[test]
    fn gated_feature_in_requires_is_refused() {
        let problems = declaration_problems(
            r#"
            [features.sha1-checked]
            kind = "gated"
            [suites.shared]
            requires = ["sha1-checked"]
            [targets.native]
            missing-features = []
            "#,
            r#"cases = [{ name = "probe/check" }]"#,
        );
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("classified Gated"));
    }

    /// A lockfile feature tag outside the [features] table is refused —
    /// the typo guard for case tagging.
    #[test]
    fn unclassified_lock_tag_is_refused() {
        let problems = declaration_problems(
            r#"
            [suites.shared]
            [targets.native]
            missing-features = []
            "#,
            r#"cases = [{ name = "alg/src/tc1/whole", features = ["sha1-cheked"] }]"#,
        );
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("\"sha1-cheked\", which is not classified"));
    }

    #[test]
    fn group_of_splits_suites_and_probes() {
        assert_eq!(
            group_of("aes-gcm/wycheproof/tc42/bytes"),
            "aes-gcm/wycheproof"
        );
        assert_eq!(group_of("probe/sha1-checked-postures"), "probe");
        assert_eq!(
            group_of("sha2/nist-cavp/sha256-len8/whole"),
            "sha2/nist-cavp"
        );
    }

    #[test]
    fn complete_results_validate() {
        assert_eq!(
            validate(&file("native", "shared", full_results())),
            Vec::<String>::new()
        );
    }

    #[test]
    fn missing_case_is_a_problem() {
        let mut results = full_results();
        results.remove(1);
        let problems = validate(&file("native", "shared", results));
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("produced no result"), "{problems:?}");
    }

    #[test]
    fn extra_case_is_a_problem() {
        let mut results = full_results();
        results.push(case("alg/src/tc99/whole", &[], Outcome::Pass));
        let problems = validate(&file("native", "shared", results));
        assert!(
            problems[0].contains("not in the suite lockfile"),
            "{problems:?}"
        );
    }

    #[test]
    fn duplicate_case_is_a_problem() {
        let mut results = full_results();
        results.push(case("probe/check", &[], Outcome::Pass));
        let problems = validate(&file("native", "shared", results));
        assert!(problems[0].contains("duplicate case"), "{problems:?}");
    }

    #[test]
    fn feature_tag_drift_is_a_problem() {
        let mut results = full_results();
        results[1].features.clear();
        let problems = validate(&file("native", "shared", results));
        assert!(problems[0].contains("feature tags"), "{problems:?}");
    }

    #[test]
    fn unknown_outcome_is_a_problem() {
        let mut results = full_results();
        results[0].outcome = Outcome::Unknown;
        let problems = validate(&file("native", "shared", results));
        assert!(
            problems[0].contains("not pass/fail/skipped"),
            "{problems:?}"
        );
    }

    #[test]
    fn missing_declaration_drift_is_a_problem() {
        let mut file = file("web", "shared", full_results());
        file.missing_features.clear();
        let problems = validate(&file);
        assert!(
            problems[0].contains("targets.toml declares"),
            "{problems:?}"
        );
    }

    #[test]
    fn results_for_an_excluded_suite_are_a_problem() {
        let problems = validate(&file("composed-like", "signing", full_results()));
        assert!(
            problems
                .iter()
                .any(|p| p.contains("missing-features exclude")),
            "{problems:?}"
        );
    }

    #[test]
    fn undeclared_suite_is_a_problem() {
        // "mystery" has no [suites] entry and no lock.
        let problems = validate(&file("native", "mystery", full_results()));
        assert!(
            problems
                .iter()
                .any(|p| p.contains("not declared in targets.toml")),
            "{problems:?}"
        );
    }

    #[test]
    fn unknown_suite_is_a_problem() {
        let problems = validate(&file("native", "mystery", full_results()));
        assert!(
            problems.iter().any(|p| p.contains("no lockfile for suite")),
            "{problems:?}"
        );
    }

    #[test]
    fn undeclared_target_is_a_problem() {
        let problems = validate(&file("rogue", "shared", full_results()));
        assert!(
            problems[0].contains("not declared in targets.toml"),
            "{problems:?}"
        );
    }

    #[test]
    fn duplicate_lock_case_is_a_problem() {
        let err = parse_lock(
            r#"
            cases = [
                { name = "probe/check" },
                { name = "probe/check" },
            ]
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicate case"), "{err}");
    }

    #[test]
    fn presence_is_derived_from_suite_requirements() {
        let files = vec![
            file("native", "shared", full_results()),
            file("composed-like", "shared", full_results()),
        ];
        let mut problems = Vec::new();
        let mut warnings = Vec::new();
        check_presence(&targets(), &files, &mut problems, &mut warnings);
        // native/signing is required and absent; composed-like/signing is
        // excluded (it is missing ecdsa-sign, which the suite requires);
        // web/shared and web/signing are optional.
        assert_eq!(
            problems,
            vec!["native/signing: no results file".to_string()]
        );
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].contains("web/shared"), "{warnings:?}");
        assert!(warnings[1].contains("web/signing"), "{warnings:?}");
    }

    #[test]
    fn duplicate_target_suite_pair_is_a_problem() {
        let files = vec![
            file("native", "shared", full_results()),
            file("native", "shared", full_results()),
        ];
        let mut problems = Vec::new();
        let mut warnings = Vec::new();
        check_presence(&targets(), &files, &mut problems, &mut warnings);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("2 results files for one")),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("native/signing: no results file")),
            "{problems:?}"
        );
    }

    #[test]
    fn json_out_aligns_outcomes_with_lock_order() {
        let mut results = full_results();
        results[1] = case("alg/src/tc2/whole", &["sha1-checked"], Outcome::Skipped);
        results[1].detail = "feature declared missing".to_string();
        results[2] = case("probe/check", &[], Outcome::Fail);
        results[2].detail = "boom".to_string();
        let files = vec![file("native", "shared", results)];
        let locks = BTreeMap::from([("shared".to_string(), lock())]);

        let json = render_json(&targets(), &locks, &files).unwrap();
        let data: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Cases follow the lockfile order and carry suite + feature tags.
        let names: Vec<&str> = data["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            ["alg/src/tc1/whole", "alg/src/tc2/whole", "probe/check"]
        );
        assert_eq!(data["cases"][0]["suite"], "shared");
        assert_eq!(data["cases"][0].get("features"), None);
        assert_eq!(data["cases"][1]["features"][0], "sha1-checked");

        // Outcome columns align to the case order; targets without results
        // render null cells.
        assert_eq!(
            data["outcomes"]["native"],
            serde_json::json!(["p", "s", "f"])
        );
        assert_eq!(
            data["outcomes"]["web"],
            serde_json::json!([null, null, null])
        );

        // Details are sparse, keyed by case index, fail/skip only.
        assert_eq!(data["details"]["native"]["1"], "feature declared missing");
        assert_eq!(data["details"]["native"]["2"], "boom");
        assert_eq!(data["details"]["native"].get("0"), None);

        // Target facts ride along for the viewer.
        assert_eq!(
            data["targets"]["web"]["missing-features"][0],
            "sha1-checked"
        );
        assert_eq!(data["targets"]["web"]["optional"], true);
        assert_eq!(data["suites"]["signing"]["requires"][0], "ecdsa-sign");
    }

    #[test]
    fn json_out_treats_unknown_outcomes_as_absent() {
        let mut results = full_results();
        results[0] = case("alg/src/tc1/whole", &[], Outcome::Unknown);
        let files = vec![file("native", "shared", results)];
        let locks = BTreeMap::from([("shared".to_string(), lock())]);
        let json = render_json(&targets(), &locks, &files).unwrap();
        let data: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            data["outcomes"]["native"],
            serde_json::json!([null, "p", "p"])
        );
    }
}
