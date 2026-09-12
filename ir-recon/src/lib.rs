//! IRScan - read-only Windows endpoint triage.
//!
//! The crate is split so that every decision-making part is pure and unit-testable
//! on any host, while all operating-system access is funnelled through `collect`
//! (fallible collectors) and `win` (the only module containing `unsafe`).
//!
//! See `docs/spec.md` (requirements) and `docs/architecture.md` (design).

// The crate-wide lints above target production code. In test code, `panic!`,
// `unwrap` and `expect` ARE the assertion mechanism, so they are lifted for the
// test configuration only - never for a shipped binary.
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]

pub mod collect;
pub mod known_services;
pub mod logaudit;
pub mod model;
pub mod monitor;
pub mod remediate;
pub mod remote_tools;
pub mod report;
pub mod rules;
pub mod signatures;
pub mod text;
pub mod ui;
pub mod win;

#[cfg(test)]
mod tests {
    //! Tests for build-level properties that no other module can assert: the manifest that
    //! decides how Windows starts this program.

    /// The manifest must ask for administrator, and say so in a form Windows accepts.
    ///
    /// This is not a cosmetic check. Without the manifest the binary runs `asInvoker`, no
    /// UAC prompt appears, and the scan silently loses the Security event log, Prefetch and
    /// the image paths of protected processes - three blind spots and no warning, which is
    /// the failure mode this whole tool is built to avoid.
    ///
    /// `tests/manifest.rs` asserts the rendered file; here we assert the two things a
    /// reader of the source can check, because the quoting defect is invisible in review:
    /// an unquoted `level=` value makes mt.exe emit invalid XML, and Windows then refuses to
    /// start the program with a side-by-side configuration error that never mentions the
    /// manifest. That cost a build cycle to find, so it is pinned.
    #[test]
    fn the_manifest_requests_administrator_and_is_well_formed_xml() {
        let text = include_str!("../app.manifest");

        assert!(
            text.contains("level=\"requireAdministrator\""),
            "the manifest must request administrator"
        );
        // Double quotes, not single: XML attributes require them, and an unquoted value is
        // what produced the side-by-side failure.
        assert!(
            text.contains("uiAccess=\"false\""),
            "uiAccess must be false: the tool must not drive higher-integrity windows"
        );
        // Phrased as a positive predicate rather than a negated assert!: a leading `!`
        // before an identifier is rewritten by the tooling this was authored with, and
        // `assert_eq!(x, false)` is rejected by this crate's own clippy gate.
        assert!(
            text.contains("asInvoker").eq(&false),
            "asInvoker contradicts requireAdministrator"
        );

        // The level must be inside trustInfo/security/requestedPrivileges, which is the
        // only place the OS reads it from. A well-formed file that puts it elsewhere is
        // accepted by XML parsers and ignored by Windows.
        let trust = text.find("<trustInfo").expect("trustInfo present");
        let level = text.find("requestedExecutionLevel").expect("level present");
        let end = text.find("</trustInfo>").expect("trustInfo closed");
        assert!(
            trust < level && level < end,
            "requestedExecutionLevel must sit inside trustInfo"
        );
    }

    /// The build must actually embed the manifest.
    ///
    /// A checked-in `app.manifest` that nothing passes to the linker is a file that reads
    /// as a guarantee and provides none - which is exactly what this repository had before
    /// the change: no `.rsrc` section, no UAC prompt, and a comment claiming otherwise.
    /// `build.rs` is the only place that can wire it, so the assertion is on its source.
    #[test]
    fn the_build_passes_the_manifest_to_the_linker() {
        let build = include_str!("../build.rs");

        // Only the arguments that are actually emitted count. Asserting on the whole file
        // is useless here, and that is not hypothetical: the first version of this test
        // passed with the flag deleted, because `build.rs` explains `/MANIFEST:EMBED` in a
        // comment and the comment stayed. A test that a comment can satisfy asserts nothing.
        let emitted: String = build
            .lines()
            .filter(|l| l.contains("rustc-link-arg"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            emitted.contains("/MANIFEST:EMBED"),
            "MANIFEST:EMBED must be emitted, or no manifest resource is produced"
        );
        // Single quotes around the values, per the linker's grammar.
        assert!(
            emitted.contains("level='requireAdministrator'"),
            "the emitted level must be single-quoted for mt.exe"
        );
        assert!(
            emitted.contains("uiAccess='false'"),
            "the emitted uiAccess must be false"
        );
        // The form the docs suggest for a quoted *fragment* is wrong through -C link-arg=:
        // the double quotes reach mt.exe literally and end up inside the attribute name.
        // Written as assert_eq! against false rather than a negated assert!, because a
        // leading `!` before an identifier is rewritten by the tooling this was authored
        // with and silently becomes a shell call.
        // Only the emitted linker arguments count. The bad form is *described* in a
        // comment in build.rs so the next reader knows why it is wrong, and a naive
        // substring search over the whole file finds that explanation and fails.
        let quoted = "/MANIFESTUAC:\"";
        let emitted_quoted_fragment = emitted.lines().any(|l| l.contains(quoted));
        assert!(
            emitted_quoted_fragment.eq(&false),
            "a quoted fragment breaks through -C link-arg=; use the unquoted form"
        );
    }
}
