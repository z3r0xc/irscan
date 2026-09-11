# IRScan — Architecture (ADD)

Status: v0.1
Companion to `spec.md` (WHAT). This document is HOW, and why.

---

## 1. Context

```
   [ elevated console ]
            |
            v
      +-----------+      reads only      +-----------------------------+
      |  irscan   | ------------------> | Windows 10 host under test  |
      |   (exe)   | <------------------ | registry, Win32 APIs,       |
      +-----------+    observations     | event logs, filesystem      |
            |                           +-----------------------------+
            | writes
            v
   report.txt / report.json   (the only artefact the tool creates)
```

The tool is a **producer of observations**, not a decision maker. Everything it prints is derived
from something it read, and the raw evidence travels with the finding so a human can overrule it.

## 2. Module map and dependency direction

```
src/
  main.rs            CLI parsing, elevation, collector wiring, exit codes, progress
  model.rs           Finding, Severity, Haystack, ScanContext, Verdict   (no OS access)
  rules.rs           pure classification, severity policy, verdict       (no OS access)
  text.rs            pure sanitisation / truncation / basename           (no OS access)
  signatures.rs      matcher over the generated database                 (no OS access)
  report.rs          plain text + JSON rendering (the artefact)          (no OS access)
  ui.rs              styled console view: palette, glyphs, wrapping      (no OS access)
  collect/
    mod.rs           Collector trait, CollectError, Progress, run_all_with (isolation)
    processes.rs     sysinfo + win::sig (path, command line, owner, trust)
    services.rs      SCM enumeration + registry Start/ImagePath/account
    autoruns.rs      Run keys, Winlogon, AppInit_DLLs, IFEO, BootExecute
    tasks.rs         %WINDIR%\System32\Tasks XML (pure parser + thin IO)
    network.rs       GetExtendedTcpTable / GetExtendedUdpTable
    events.rs        EvtQuery XML -> a pure parser -> findings (FR-10)
    accounts.rs      local accounts, Administrators membership
    remote_access.rs RDP / WinRM / Remote Assistance config, listeners
    defender.rs      Defender state, exclusions, detection history
    inputfilters.rs  device-class UpperFilters / LowerFilters (FR-12)
    filesystem.rs    drop locations, prefetch, recent executables
    traces.rs        product evidence files (connection_trace.txt, ...)
    wmi.rs           ROOT\SUBSCRIPTION consumers and filters (fileless persistence)
    yara.rs          content scanning of the files the other collectors found
  win/
    mod.rs           the ONLY module allowed to contain `unsafe`
    strings.rs       UTF-16 <-> Rust conversion, environment expansion
    reg.rs           registry read helper (open / enum / size-then-read)
    sig.rs           WinVerifyTrust (embedded + catalog) + version resources
    hash.rs          bounded SHA-256 of a file
    events.rs        EvtQuery / EvtNext / EvtRender, newest first
    services.rs      OpenSCManagerW / EnumServicesStatusExW
    net.rs           owning-PID TCP/UDP tables
    accounts.rs      NetUserEnum / NetLocalGroupGetMembers
    wmi.rs           raw COM over the Wbem vtables, hand-declared
    elevate.rs       self-elevation via ShellExecuteExW "runas"
    console.rs       ENABLE_VIRTUAL_TERMINAL_PROCESSING probe
  known_services.rs  generated table of 70 Windows service names (see below)
rules/
  irscan.yar         our own bundled YARA rules (embedded with include_str!)
tools/
  gen_known_services.py   vendoring step for known_services.rs (not part of the build)
  check_generated.sh      proves build.rs output is deterministic
```

`known_services.rs` is **generated, not written**: `tools/gen_known_services.py` parses
a TypeScript knowledge base from AdventDevInc/kudu (MIT) and emits a sorted, deduplicated
Rust table whose re-run is byte-identical. Hand-transcribing seventy security-relevant
service names is how a tool acquires a quiet typo that makes it lie, so the table is
produced mechanically and its generator is committed alongside it. The header of the
generated file names the upstream path and licence. `tools/` is deliberately outside the
build: `raw/` is not in version control, so regeneration is a vendoring step run by hand,
not something CI could repeat.

**Dependency direction is strictly downward:** `main -> collect -> {model, rules, signatures, win}`.
`model`, `rules`, `text`, `signatures` and `report` never touch the OS, which is what makes them
unit-testable on any machine, including CI without Windows.

## 3. The `Collector` contract

```rust
pub trait Collector {
    fn name(&self) -> &'static str;
    fn run(&self, ctx: &mut ScanContext) -> Result<(), CollectError>;
}
```

Rules:

- A collector may only push findings, haystacks, records and warnings into `ctx`. It never prints.
- A collector returns `Err` only for "cannot run at all"; partial success is `Ok` plus warnings.
- A failing collector must not abort the scan: `collect::run_all` records the error in
  `warnings[]` and continues. This makes the reliability tactic structural rather than aspirational
  (`a_failing_collector_does_not_stop_the_others`).
- Collectors execute in a fixed order so two runs on an unchanged host produce identical reports.
  Diff-ability beats parallelism here.

## 4. Data flow

```
Collector --(observations)--> ScanContext { records, haystacks, findings }
                                     |
                     rules::*  (severity policy, per observation)
                                     |
                     signatures::match_all(&ctx.haystack)
                                     |
                          rules::verdict(&ctx.findings, warnings)
                                     |
                     report::render_text / render_json -> stdout + file
```

`rules` is the single place where severity is decided. A finding's severity must never be
constructed ad hoc inside a collector, otherwise the policy becomes untestable and drifts.

## 5. Quality-attribute tactics (ADD, traceable to spec section 6)

### 5.1 Security (priority 1)

| Threat | Tactic | Where |
|--------|--------|-------|
| Command injection via a collected string (service path, task action, file name) | Never build a command line; use Win32 APIs for every action | `win/*`; no `std::process::Command` anywhere in the crate |
| Hostile output turning into terminal attack or log corruption | One sanitiser, applied at every boundary; complete escape-sequence removal, not just ESC | `text.rs`, `ScanContext::note` |
| Path traversal / symlink escape while walking | Skip reparse points; compare against the walk root | `collect/filesystem.rs` |
| Buffer overrun in FFI | Size-then-allocate for every enumeration API; check every return code | `win/reg.rs`, `collect/services.rs` |
| The tool itself being weaponised | Read-only by default; no network; no listening socket; no dynamic loading | whole binary |

### 5.2 Reliability (priority 2)

- `unwrap`/`expect`/`panic` are denied by lint; every fallible step returns a `Result` or is
  explicitly defaulted with a recorded warning.
- Hard caps: `MAX_EVENTS`, `MAX_FILES`, `MAX_DEPTH`, `MAX_BYTES_READ`, `MAX_STRING`.
- Event queries carry explicit XPath time windows and a maximum event count, so a multi-gigabyte
  Security log cannot hang the scan.

### 5.3 Presentation is not part of the artefact

`ui` and `report` render the same `ScanContext` for two audiences, and the split is a
correctness requirement rather than a style choice:

* the file must be byte-stable and colourless, because it is what gets copied, hashed
  and diffed between two runs of the same machine;
* the console must be readable at a glance, which means glyphs, wrapping and
  collapsing repeated findings.

They cannot be the same function without one of those two properties being lost. The
styled view is therefore derived from the plain one at render time, and a test asserts
that a plain run contains no ESC byte at all.

### 5.4 Testability (priority 3)

Deliberate split: parsers take `&str`/`&[u8]` and return data, so the interesting logic is tested
with fixtures. The FFI layer is a thin, boring shim with no business rules in it, exercised by
`--self-test` on a real host.

## 6. FFI safety rules (`win/` only)

1. Every `unsafe` block carries a comment naming the invariant the caller must uphold.
2. Buffers are `Vec<u8>` sized from the API's required-length return value; a second call with a
   larger buffer handles the race where the required size grew in between.
3. Every returned handle is closed on every path, including error paths, via small RAII guards
   (`OwnedHandle`, `OwnedRegKey`, `OwnedEvt`).
4. `HANDLE` in windows-sys 0.61 is `*mut c_void` (verified against docs.rs); handles start as
   `ptr::null_mut()` and are compared against `INVALID_HANDLE_VALUE` where the API documents it.
5. Strings are converted lossily and NUL-trimmed; nothing panics on malformed UTF-16.
6. Structure sizes come from `size_of::<T>()`, never a hard-coded constant.
7. Struct layouts follow the SDK definitions exactly; no manual `#[repr]` guesses.

## 6.1 Content scanning (YARA)

`collect/yara.rs` adds the one axis the rest of the tool lacks: what is *inside* a file,
which is what still works when an agent is renamed and moved. Three decisions shape it:

* **It scans what was already found, not the disk.** Targets are process images, service
  images, scheduled-task actions and autostart commands - files irscan already had a
  reason to look at - so a scan stays bounded (512 files, 32 MiB each) and finishes.
* **Every rule is compiled separately.** A rule that fails to compile becomes a warning
  naming the file, because a user-supplied rule directory must never cost them the whole
  scan. yara-x advertises 99% compatibility with classic YARA, so failures are expected
  on an external corpus.
* **A match is a lead, not a verdict.** The finding carries the rule's own `severity`
  metadata, the rule's description, the file and its size, and a remediation line that
  says to corroborate it. The bundled rules are written to match *combinations* of
  symbols (a screen-capture API set, an input-injection API set) rather than single
  strings, because one symbol proves nothing.

Rule sets that cannot be redistributed are excluded by licence: `YARA-Rules/rules` is
GPL-2.0 and `elastic/protections-artifacts` is under the Elastic Licence, so neither may
be vendored into this project. `--yara-rules` lets the user point at any corpus locally
without this project redistributing it.

## 7. Signature database

`build.rs` is the **deterministic generator**: input `data/rmm_tools.json` (vendored from
mthcht/LOLRMM, Apache-2.0), output `$OUT_DIR/signatures.rs` with a single static array. Nothing is
checked in, so the database can never drift from the source; `tools/check_generated.sh` proves
determinism by building twice and comparing the generated file.

Each entry yields matchable needles by kind:

| Kind | Source field | Matched against | Strength |
|------|--------------|-----------------|----------|
| `ProcessName` | `Details.InstallationPaths` (bare file names) | process image name, compared exactly | strong |
| `Path` | `Artifacts.Disk[].File`, `EventLog[].ImagePath`, installation paths | path, command line, registry value | strong |
| `ServiceName` | `Artifacts.EventLog[].ServiceName` | service name/display name, image name, task name | strong |
| `RegistryPath` | `Artifacts.Registry[].Path` | registry key path | strong |
| `TaskName` | derived path tails | scheduled task name and action path | strong |
| `Domain` | `Artifacts.Network[].Domains` (literal hosts only) | DNS names and command lines | weak (Info) |

Two deliberate rejections:

- **Ports are not emitted.** A shared port such as 443 would match half the internet. The genuinely
  distinctive remote-control ports live in `rules::port_label` and label listeners instead.
- **Wildcards, regex fragments and `%VAR%` segments are dropped, not guessed.** `%VAR%\` prefixes
  are stripped so the literal tail still matches on any machine.

Attribution and the Apache-2.0 notice live in `THIRD_PARTY_NOTICES.md`, and the upstream source is
named in the generated file header, so provenance survives any refactor.

## 7.1 Test-only lint policy

Production code denies `unwrap`, `expect` and `panic`. Test code uses exactly those as
its assertion mechanism, so `#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used,
clippy::expect_used))]` lifts them for the test configuration only. Without that
distinction one either gives up the lints in shipped code or writes test assertions that
are worse at reporting a failure - both are worse than the two lines it takes to say so.

## 8. Why Rust

- One static binary, no runtime to install on the suspect machine. A .NET or Python tool would add
  a dependency that the machine under suspicion may have been tampered with.
- `unsafe` is explicit and auditable — the property you want in a tool that calls raw Win32 with
  attacker-influenced sizes and lengths.
- `cargo test`, `clippy` and `fmt` give deterministic, scriptable verification for CI.

## 9. Explicit limitations (honesty section)

- A kernel-mode rootkit can hide from every user-mode API used here. The tool detects user-mode and
  service-level persistence reliably; it does not prove absence.
- Without Sysmon/ETW history, a short-lived beacon that already exited leaves only prefetch, 7045
  events and the registry as evidence.
- Signature matching is name and path based: a renamed, stealthed agent with no registry trace can
  be missed. That is why behavioural signals (user-writable path, untrusted signature, active
  outbound connection, hidden task, class filter driver) carry equal weight in the verdict.
