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
pub mod model;
pub mod report;
pub mod rules;
pub mod signatures;
pub mod text;
pub mod ui;
pub mod win;
