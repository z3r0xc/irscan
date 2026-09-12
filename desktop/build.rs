//! Tauri build script.
//!
//! It embeds the front end from `ui/` into the binary and generates the ACL schema, so
//! the shipped application is one self-contained file with no asset directory beside
//! it - which matters here, because the tool is copied to another machine as a single
//! file.

fn main() {
    tauri_build::build()
}
