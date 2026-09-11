//! Build-time signature generation.
//!
//! Reads the vendored LOLRMM artifact database (`data/rmm_tools.json`) and its
//! certificate index (`data/rmm_certificates.json`) - Apache-2.0, see
//! THIRD_PARTY_NOTICES.md - and emits `$OUT_DIR/signatures.rs` with a single static
//! array. The output is deterministic: identical input produces a byte-identical
//! file, which `tools/check_generated.sh` proves by regenerating and diffing.
//!
//! Design decisions worth knowing:
//! * `InstallationPaths` entries that are a bare file name become `ProcessName`
//!   needles; entries with separators become `Path` needles.
//! * Leading `%VAR%\` prefixes are stripped instead of expanded: a needle then
//!   matches the literal tail of a real path regardless of how the environment is
//!   configured on the analysed machine.
//! * Publisher needles come from the certificate index (`company_names`,
//!   `signer_names`). This is the only axis that survives a rename of the binary,
//!   and it costs one comparison per process.
//! * Wildcards, regex fragments and GUID-ish noise are dropped rather than guessed.
//! * Ports are NOT emitted. A shared port such as 443 would match half the internet;
//!   the handful of genuinely distinctive remote-control ports live in
//!   `rules::port_label`.
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
// A build script must fail the build loudly when its input is wrong; panicking here
// is the correct behaviour, so the crate-wide lints are lifted for this file only.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Kinds understood by `src/signatures.rs`. The index is the sort key, so the
/// generated file is stable regardless of iteration order.
const KINDS: &[(&str, u8)] = &[
    ("ProcessName", 0),
    ("Path", 1),
    ("ServiceName", 2),
    ("RegistryPath", 3),
    ("TaskName", 4),
    ("Domain", 5),
    ("Publisher", 6),
];

fn main() {
    let manifest_dir = match env::var("CARGO_MANIFEST_DIR") {
        Ok(v) => v,
        Err(_) => panic!("CARGO_MANIFEST_DIR is not set; cannot locate the signature database"),
    };
    let db_path = Path::new(&manifest_dir).join("data").join("rmm_tools.json");
    let cert_path = Path::new(&manifest_dir)
        .join("data")
        .join("rmm_certificates.json");
    println!("cargo:rerun-if-changed={}", db_path.display());
    println!("cargo:rerun-if-changed={}", cert_path.display());
    println!("cargo:rerun-if-changed=build.rs");

    let raw = match fs::read_to_string(&db_path) {
        Ok(v) => v,
        Err(e) => panic!("cannot read {}: {e}", db_path.display()),
    };
    let json: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => panic!("{} is not valid JSON: {e}", db_path.display()),
    };
    let tools = match json.as_array() {
        Some(v) => v,
        None => panic!("{} must contain a JSON array of tools", db_path.display()),
    };

    // tool name -> category, so every needle can name the class of product it came
    // from. A reader of the report needs to know "remote control" from "backup".
    let mut categories: BTreeMap<String, String> = BTreeMap::new();
    for tool in tools {
        if let Some(name) = string_field(tool, "Name") {
            let category = string_field(tool, "Category").unwrap_or_default();
            categories.insert(name, category);
        }
    }

    // BTreeMap keyed by the needle gives deduplication and a stable sorted order.
    let mut needles: BTreeMap<(String, u8, String), String> = BTreeMap::new();
    let mut tool_count = 0usize;

    for tool in tools {
        let name = match string_field(tool, "Name") {
            Some(n) => n,
            None => continue,
        };
        tool_count += 1;
        let category = categories.get(&name).cloned().unwrap_or_default();

        // 1. Installation paths: bare file name -> process name, otherwise path.
        if let Some(paths) = tool
            .get("Details")
            .and_then(|d| d.get("InstallationPaths"))
            .and_then(|v| v.as_array())
        {
            for p in paths.iter().filter_map(|v| v.as_str()) {
                if !p.contains(['\\', '/']) && p.to_lowercase().ends_with(".exe") {
                    push(&mut needles, &name, &category, "ProcessName", p);
                } else if let Some(clean) = clean_needle(p) {
                    push(&mut needles, &name, &category, "Path", &clean);
                }
            }
        }

        // 2. Disk artefacts: paths to logs, databases and install locations.
        if let Some(disk) = tool
            .get("Artifacts")
            .and_then(|a| a.get("Disk"))
            .and_then(|v| v.as_array())
        {
            for d in disk {
                if let Some(f) = d.get("File").and_then(|v| v.as_str()) {
                    if let Some(clean) = clean_needle(f) {
                        push(&mut needles, &name, &category, "Path", &clean);
                    }
                }
            }
        }

        // 3. Registry artefacts.
        if let Some(reg) = tool
            .get("Artifacts")
            .and_then(|a| a.get("Registry"))
            .and_then(|v| v.as_array())
        {
            for r in reg {
                if let Some(p) = r.get("Path").and_then(|v| v.as_str()) {
                    if let Some(clean) = clean_needle(p) {
                        push(&mut needles, &name, &category, "RegistryPath", &clean);
                    }
                }
            }
        }

        // 4. Service names and image paths recorded in event-log artefacts.
        if let Some(ev) = tool
            .get("Artifacts")
            .and_then(|a| a.get("EventLog"))
            .and_then(|v| v.as_array())
        {
            for e in ev {
                if let Some(s) = e.get("ServiceName").and_then(|v| v.as_str()) {
                    if let Some(clean) = clean_needle(s) {
                        push(&mut needles, &name, &category, "ServiceName", &clean);
                    }
                }
                if let Some(i) = e.get("ImagePath").and_then(|v| v.as_str()) {
                    if let Some(clean) = clean_needle(i) {
                        push(&mut needles, &name, &category, "Path", &clean);
                    }
                }
            }
        }

        // 5. Network domains. Literal host names only.
        if let Some(net) = tool
            .get("Artifacts")
            .and_then(|a| a.get("Network"))
            .and_then(|v| v.as_array())
        {
            for n in net {
                if let Some(domains) = n.get("Domains").and_then(|v| v.as_array()) {
                    for d in domains.iter().filter_map(|v| v.as_str()) {
                        if let Some(clean) = clean_domain(d) {
                            push(&mut needles, &name, &category, "Domain", &clean);
                        }
                    }
                }
            }
        }
    }

    // 6. Publishers from the certificate index. Optional file: a missing index
    //    degrades coverage but must not break the build.
    let mut publisher_count = 0usize;
    if let Ok(certs_raw) = fs::read_to_string(&cert_path) {
        if let Ok(certs) = serde_json::from_str::<serde_json::Value>(&certs_raw) {
            if let Some(list) = certs.as_array() {
                for entry in list {
                    let name = match string_field(entry, "name") {
                        Some(n) => n,
                        None => continue,
                    };
                    let category = categories.get(&name).cloned().unwrap_or_default();
                    for key in ["company_names", "signer_names"] {
                        if let Some(arr) = entry.get(key).and_then(|v| v.as_array()) {
                            for value in arr.iter().filter_map(|v| v.as_str()) {
                                if let Some(clean) = clean_publisher(value) {
                                    publisher_count += 1;
                                    push(&mut needles, &name, &category, "Publisher", &clean);
                                }
                            }
                        }
                    }
                    if let Some(arr) = entry.get("search_names").and_then(|v| v.as_array()) {
                        for value in arr.iter().filter_map(|v| v.as_str()) {
                            if !value.contains(['\\', '/'])
                                && value.to_lowercase().ends_with(".exe")
                            {
                                push(&mut needles, &name, &category, "ProcessName", value);
                            } else if let Some(clean) = clean_needle(value) {
                                push(&mut needles, &name, &category, "Path", &clean);
                            }
                        }
                    }
                }
            }
        }
    }

    let mut out = String::with_capacity(needles.len() * 110 + 1024);
    out.push_str(
        "// @generated by build.rs from data/rmm_tools.json + data/rmm_certificates.json\n",
    );
    out.push_str("// Source: magicsword-io/LOLRMM (Apache-2.0). See THIRD_PARTY_NOTICES.md.\n");
    out.push_str("/// One matchable string taken from the upstream artifact database.\n");
    out.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n");
    out.push_str("pub struct Signature {\n");
    out.push_str("    pub tool: &'static str,\n");
    out.push_str("    /// Upstream product category, e.g. \"Remote Monitoring and Management\".\n");
    out.push_str("    pub category: &'static str,\n");
    out.push_str("    pub kind: SigKind,\n");
    out.push_str("    pub needle: &'static str,\n");
    out.push_str("}\n\n");
    out.push_str("pub static SIGNATURES: &[Signature] = &[\n");
    for ((tool, kind_idx, needle), category) in &needles {
        let kind_name = KINDS
            .iter()
            .find(|(_, i)| i == kind_idx)
            .map(|(n, _)| *n)
            .unwrap_or("Path");
        out.push_str(&format!(
            "    Signature {{ tool: \"{}\", category: \"{}\", kind: SigKind::{}, needle: \"{}\" }},\n",
            escape(tool),
            escape(category),
            kind_name,
            escape(needle)
        ));
    }
    out.push_str("];\n");

    let out_dir = match env::var("OUT_DIR") {
        Ok(v) => v,
        Err(_) => panic!("OUT_DIR is not set"),
    };
    let dest: PathBuf = Path::new(&out_dir).join("signatures.rs");
    if let Err(e) = fs::write(&dest, out) {
        panic!("cannot write {}: {e}", dest.display());
    }

    println!(
        "cargo:warning=irscan: {} tools, {} publisher names -> {} signature needles",
        tool_count,
        publisher_count,
        needles.len()
    );
}

/// A string-valued field that may also be an array of strings.
fn string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    match value.get(key) {
        Some(serde_json::Value::String(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
        Some(serde_json::Value::Array(items)) => {
            let parts: Vec<String> = items
                .iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join(", "))
            }
        }
        _ => None,
    }
}

fn push(
    map: &mut BTreeMap<(String, u8, String), String>,
    tool: &str,
    category: &str,
    kind: &str,
    needle: &str,
) {
    let idx = match KINDS.iter().find(|(n, _)| *n == kind) {
        Some((_, i)) => *i,
        None => return,
    };
    let value = needle.trim().to_lowercase();
    if value.chars().count() < 3 {
        return;
    }
    map.entry((tool.to_string(), idx, value))
        .or_insert_with(|| category.to_string());
}

/// Strip `%VAR%\` prefixes and reject anything that cannot be matched literally.
fn clean_needle(raw: &str) -> Option<String> {
    let mut s = raw.trim().to_string();

    while s.starts_with('%') {
        let end = s.find('%').filter(|e| *e > 0)?;
        let rest = &s[end + 1..];
        let rest = rest.trim_start_matches(['\\', '/']);
        if rest.is_empty() {
            return None;
        }
        s = rest.to_string();
    }

    if s.contains(['%', '*', '?', '[', ']', '$']) {
        return None;
    }

    let s = s.replace('/', "\\");
    let s = s.trim_matches('\\').trim().to_string();
    if s.chars().count() < 4 {
        return None;
    }
    if !s.chars().any(|c| c.is_ascii_alphanumeric()) {
        return None;
    }

    // A needle must be specific enough to mean something. Without this check an
    // upstream `InstallationPaths` entry of "setup" became a needle that matched
    // every installer on the machine, producing three false "remote-control
    // product detected" findings on a clean host. A usable needle is either a path
    // (it contains a separator) or a file name (it carries an extension).
    let has_separator = s.contains('\\');
    let has_extension = match s.rsplit_once('.') {
        Some((stem, ext)) => {
            !stem.is_empty()
                && (2..=5).contains(&ext.len())
                && ext.chars().all(|c| c.is_ascii_alphabetic())
        }
        None => false,
    };
    if !has_separator && !has_extension {
        return None;
    }
    if !has_separator && s.chars().count() < 6 {
        return None;
    }
    Some(s)
}

/// Publisher names keep punctuation (commas, dots, ampersands) because that is how
/// they appear in a signature; only wildcards and regex fragments are refused.
fn clean_publisher(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.chars().count() < 4 || s.contains(['*', '[', ']', '?', '$']) {
        return None;
    }
    if !s.chars().any(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    Some(s.to_string())
}

/// Domains must be literal host names: no wildcards, no regex, and at least one dot.
fn clean_domain(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.contains(['*', '[', ']', '?', '$', ' ', ':']) || !s.contains('.') {
        return None;
    }
    if s.chars().count() < 5 || !s.chars().any(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    Some(s.to_lowercase())
}

fn escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '"' => o.push_str("\\\""),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => o.push(c),
        }
    }
    o
}
