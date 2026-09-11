//! Embedded signature database and the single matcher pass.
//!
//! Collectors push [`crate::model::Haystack`] values; this module is the only place
//! that knows about the database. That keeps every collector free of detection
//! policy and makes the policy testable with a hand-written signature slice.

use std::collections::BTreeMap;

use crate::model::{Finding, Haystack, HaystackKind, Severity};

include!(concat!(env!("OUT_DIR"), "/signatures.rs"));

/// Which collected string a signature kind is allowed to match against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SigKind {
    ProcessName,
    Path,
    ServiceName,
    RegistryPath,
    TaskName,
    Domain,
    Publisher,
}

impl SigKind {
    fn accepts(self, hay: HaystackKind) -> bool {
        match self {
            SigKind::ProcessName => hay == HaystackKind::ProcessName,
            SigKind::Path => matches!(
                hay,
                HaystackKind::Path | HaystackKind::CommandLine | HaystackKind::RegistryPath
            ),
            SigKind::ServiceName => matches!(
                hay,
                HaystackKind::ServiceName
                    | HaystackKind::ServiceDisplayName
                    | HaystackKind::ProcessName
                    | HaystackKind::TaskName
            ),
            SigKind::RegistryPath => matches!(hay, HaystackKind::RegistryPath | HaystackKind::Path),
            SigKind::TaskName => matches!(hay, HaystackKind::TaskName | HaystackKind::Path),
            SigKind::Domain => matches!(hay, HaystackKind::Domain | HaystackKind::CommandLine),
            // The publisher axis only reads company/product strings. It is the one
            // signal that survives a rename of the binary, so it carries its weight
            // even though it is a substring test.
            SigKind::Publisher => hay == HaystackKind::ProductName,
        }
    }

    /// A bare name or publisher match is strong evidence the product is installed;
    /// a domain alone is a hint that needs corroboration before it is raised.
    fn is_strong(self) -> bool {
        !matches!(self, SigKind::Domain)
    }

    pub fn label(self) -> &'static str {
        match self {
            SigKind::ProcessName => "process name",
            SigKind::Path => "path",
            SigKind::ServiceName => "service name",
            SigKind::RegistryPath => "registry key",
            SigKind::TaskName => "task name",
            SigKind::Domain => "domain",
            SigKind::Publisher => "publisher",
        }
    }
}

fn normalize(s: &str) -> String {
    s.replace('/', "\\").to_lowercase()
}

/// Does any path component or command-line token equal `needle` exactly?
///
/// Used for needles that carry no separator: such a needle is a file name, and
/// substring matching on a file name is how `sqlite3.dll` came to match
/// `e_sqlite3.dll` - exactly the false lead this function prevents.
fn contains_component(candidate: &str, needle: &str) -> bool {
    candidate
        .split(|c: char| c == '\\' || c == '/' || c.is_whitespace() || c == '"')
        .any(|component| component == needle)
}

fn matches_one(sig: &Signature, hay: &Haystack) -> bool {
    if !sig.kind.accepts(hay.kind) {
        return false;
    }
    // Bind as &str, not &&str: `str::as_str` is unstable and the double reference
    // would silently resolve to it.
    let needle: &str = sig.needle;
    if needle.chars().count() < 3 {
        return false;
    }

    match sig.kind {
        // Image names are compared exactly on the final path component, so that
        // "agent.exe" cannot be matched by an unrelated "my-agent-helper.exe".
        SigKind::ProcessName => normalize(crate::text::basename(&hay.value)) == needle,
        // A path needle carrying a separator is a fragment and is searched for as
        // one; without a separator it is a file name and must match a whole
        // component of the value.
        SigKind::Path => {
            let candidate = normalize(&hay.value);
            if needle.contains('\\') {
                candidate.contains(needle)
            } else {
                contains_component(&candidate, needle)
            }
        }
        // Everything else is a literal substring test on a normalized string.
        _ => normalize(&hay.value).contains(needle),
    }
}

/// Run the database against collected strings, returning one finding per product.
pub fn match_all(haystack: &[Haystack]) -> Vec<Finding> {
    match_against(SIGNATURES, haystack)
}

/// Testable core: same algorithm, caller-supplied signature slice.
pub fn match_against(sigs: &[Signature], haystack: &[Haystack]) -> Vec<Finding> {
    // tool -> (strongest kind seen, category, evidence lines)
    let mut hits: BTreeMap<&str, (SigKind, &str, Vec<String>)> = BTreeMap::new();

    for hay in haystack {
        for sig in sigs {
            if !matches_one(sig, hay) {
                continue;
            }
            let entry = hits
                .entry(sig.tool)
                .or_insert((sig.kind, sig.category, Vec::new()));
            if sig.kind.is_strong() && !entry.0.is_strong() {
                entry.0 = sig.kind;
            }
            // The needle is part of the evidence on purpose. Without it a reader
            // cannot tell a precise match ("agent.exe") from a loose one ("setup.exe"),
            // and a finding nobody can audit is a finding nobody should trust.
            let line = format!(
                "{} '{}' matched {} needle '{}' ({})",
                hay.kind.label(),
                hay.value,
                sig.kind.label(),
                sig.needle,
                hay.origin
            );
            if entry.2.len() < 8 && !entry.2.iter().any(|l| l == &line) {
                entry.2.push(line);
            }
        }
    }

    hits.into_iter()
        .map(|(tool, (kind, category, evidence))| {
            let severity = if kind.is_strong() {
                Severity::Med
            } else {
                Severity::Info
            };
            let title = if category.is_empty() {
                format!("Known monitoring / remote-control product detected: {tool}")
            } else {
                format!("Monitoring / remote-control product detected: {tool} [{category}]")
            };
            let mut f = Finding::new(severity, "signature", title).remediation(format!(
                "Identify this product before deleting anything: if an employer or an IT \
                 department installed it, removal is a policy matter, not a technical one. \
                 Upstream reference: magicsword-io/LOLRMM entry '{tool}'."
            ));
            for e in evidence {
                f = f.evidence(e);
            }
            f
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(tool: &'static str, kind: SigKind, needle: &'static str) -> Signature {
        Signature {
            tool,
            category: "",
            kind,
            needle,
        }
    }

    fn sig_cat(
        tool: &'static str,
        category: &'static str,
        kind: SigKind,
        needle: &'static str,
    ) -> Signature {
        Signature {
            tool,
            category,
            kind,
            needle,
        }
    }

    fn hay(kind: HaystackKind, value: &str) -> Haystack {
        Haystack::new(kind, value, "test")
    }

    #[test]
    fn process_name_matches_exactly_not_by_substring() {
        let sigs = [sig("Acme Agent", SigKind::ProcessName, "agent.exe")];
        let hit = match_against(&sigs, &[hay(HaystackKind::ProcessName, "agent.exe")]);
        assert_eq!(hit.len(), 1);
        let miss = match_against(
            &sigs,
            &[hay(HaystackKind::ProcessName, "my-agent-helper.exe")],
        );
        assert!(miss.is_empty(), "image names must compare exactly");
    }

    #[test]
    fn matching_is_case_insensitive_and_separator_agnostic() {
        let sigs = [sig("AnyDesk", SigKind::Path, "anydesk\\ad_svc.trace")];
        let hit = match_against(
            &sigs,
            &[hay(
                HaystackKind::Path,
                "C:/ProgramData/AnyDesk/ad_svc.trace",
            )],
        );
        assert_eq!(hit.len(), 1);
    }

    #[test]
    fn path_needle_matches_inside_a_command_line() {
        let sigs = [sig("Acme", SigKind::Path, "acme\\agent.exe")];
        let hit = match_against(
            &sigs,
            &[hay(
                HaystackKind::CommandLine,
                r#""C:\ProgramData\Acme\agent.exe" --silent"#,
            )],
        );
        assert_eq!(hit.len(), 1);
    }

    #[test]
    fn one_finding_per_tool_with_capped_evidence() {
        let sigs = [
            sig("Acme", SigKind::ProcessName, "acme.exe"),
            sig("Acme", SigKind::Path, "acme\\agent.exe"),
            sig("Acme", SigKind::RegistryPath, "acme"),
        ];
        let haystack = [
            hay(HaystackKind::ProcessName, "acme.exe"),
            hay(HaystackKind::Path, r"C:\ProgramData\Acme\agent.exe"),
            hay(HaystackKind::RegistryPath, r"HKLM\SOFTWARE\Acme"),
        ];
        let hits = match_against(&sigs, &haystack);
        assert_eq!(
            hits.len(),
            1,
            "needles for one tool collapse into one finding"
        );
        assert!(hits[0].evidence.len() <= 8);
        assert_eq!(hits[0].severity, Severity::Med);
    }

    #[test]
    fn weak_kind_is_reported_at_info_severity() {
        let sigs = [sig("Acme Cloud", SigKind::Domain, "acme-cloud.example")];
        let hits = match_against(&sigs, &[hay(HaystackKind::Domain, "acme-cloud.example")]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Info);
    }

    #[test]
    fn strong_kind_upgrades_a_product_that_also_matched_weakly() {
        let sigs = [
            sig("Acme", SigKind::Domain, "acme.example"),
            sig("Acme", SigKind::ServiceName, "acmesvc"),
        ];
        let haystack = [
            hay(HaystackKind::Domain, "acme.example"),
            hay(HaystackKind::ServiceName, "AcmeSvc"),
        ];
        let hits = match_against(&sigs, &haystack);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Med);
    }

    #[test]
    fn publisher_match_survives_a_renamed_binary() {
        // The point of the publisher axis: the file name is meaningless, but the
        // signature still says who built it.
        let sigs = [sig_cat(
            "Kickidler",
            "Employee Monitoring",
            SigKind::Publisher,
            "kickidler llc",
        )];
        let hits = match_against(&sigs, &[hay(HaystackKind::ProductName, "Kickidler LLC")]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Med);
        assert!(hits[0].title.contains("Employee Monitoring"));
    }

    #[test]
    fn publisher_needle_never_matches_a_process_name() {
        let sigs = [sig("Acme", SigKind::Publisher, "acme corporation")];
        assert!(
            match_against(&sigs, &[hay(HaystackKind::ProcessName, "acme corporation")]).is_empty()
        );
    }

    #[test]
    fn kind_gating_prevents_nonsense_matches() {
        // A domain needle must not match a process name that happens to contain it.
        let sigs = [sig("Acme", SigKind::Domain, "acme.example")];
        assert!(match_against(&sigs, &[hay(HaystackKind::ProcessName, "acme.example")]).is_empty());
    }

    #[test]
    fn a_bare_file_name_needle_must_match_a_whole_component() {
        // The real case: an upstream entry of `sqlite3.dll` must not match
        // `e_sqlite3.dll`, which is what produced a false "Xshell [RAT]" finding.
        let sigs = [sig("Xshell", SigKind::Path, "sqlite3.dll")];
        assert!(match_against(
            &sigs,
            &[hay(
                HaystackKind::Path,
                r"C:\Users\b\AppData\Local\PowerToys\e_sqlite3.dll"
            )]
        )
        .is_empty());
        // A genuine file name still matches, in a path and in a command line.
        assert_eq!(
            match_against(&sigs, &[hay(HaystackKind::Path, r"C:\x\sqlite3.dll")]).len(),
            1
        );
        assert_eq!(
            match_against(
                &sigs,
                &[hay(
                    HaystackKind::CommandLine,
                    r#"cmd /c "C:\x\sqlite3.dll" -q"#
                )]
            )
            .len(),
            1
        );
    }

    #[test]
    fn a_fragment_needle_still_matches_as_a_substring() {
        let sigs = [sig("Acme", SigKind::Path, "acme\\agent")];
        assert_eq!(
            match_against(&sigs, &[hay(HaystackKind::Path, r"C:\x\acme\agent.exe")]).len(),
            1
        );
    }

    #[test]
    fn short_needles_are_ignored_defensively() {
        let sigs = [sig("X", SigKind::Path, "ab")];
        assert!(match_against(&sigs, &[hay(HaystackKind::Path, "ab")]).is_empty());
    }

    #[test]
    fn real_database_loads_and_is_well_formed() {
        // Guards the generator contract: the shipped database must be usable, and
        // must actually contain every axis the tool claims to check.
        assert!(
            SIGNATURES.len() > 1000,
            "generated database looks truncated: {} needles",
            SIGNATURES.len()
        );
        assert!(SIGNATURES
            .iter()
            .all(|s| !s.needle.is_empty() && !s.tool.is_empty()));
        for kind in [
            SigKind::ProcessName,
            SigKind::Path,
            SigKind::ServiceName,
            SigKind::RegistryPath,
            SigKind::Domain,
            SigKind::Publisher,
        ] {
            assert!(
                SIGNATURES.iter().any(|s| s.kind == kind),
                "no needles of kind {kind:?} were generated"
            );
        }
    }
}
