# IRScan — Specification

Status: v0.1 (implementation baseline)
Date: 2026-09-11
Method: SDD — requirements are numbered, testable, and each maps to code and tests.

---

## 1. Problem

A second PC running Windows 10 shows signs of **interactive remote control**: the mouse moved on
its own and minimised windows opened themselves. Suspected cause: a covert employee-monitoring /
time-tracking agent that periodically captures the screen and uploads it to a server, and that may
also permit live control of mouse and keyboard. Such products deliberately present themselves as
ordinary software, and some are stealthed (no tray icon, no obvious service name, removal password).

## 2. Goal

A **single-file, read-only** Windows endpoint triage tool that:

1. enumerates every realistic execution and persistence location on a live Windows 10 host;
2. matches what it finds against an authoritative public database of 270 monitoring /
   remote-control products;
3. reports concrete, evidence-backed findings with severity and remediation steps;
4. is **safe** to run on a machine that may be actively compromised (no writes to the system, no
   network traffic, no execution of anything it inspects).

## 3. Non-goals

- Not an antivirus; does not claim a machine is clean.
- Does not remove kernel components and cannot defeat a rootkit. For a real RAT, only a clean
  reinstall from external media is a complete removal — the tool says so itself.
- Never contacts the network, never uploads anything, never phones home.
- Does not analyse the user's documents, browser history or personal files.

## 4. Users and usage

One user, running elevated, on the machine under suspicion:

```
irscan.exe                     full scan: styled console view + plain text report
irscan.exe --json out.json     machine-readable report (for diffing / CI)
irscan.exe --quick             skip slow collectors (prefetch, filesystem walk)
irscan.exe --watch 120         watch new outbound connections for 120 seconds
irscan.exe --out DIR           where to write the report
irscan.exe --self-test         run every collector once and report failures
irscan.exe --plain             never emit ANSI (also implied by NO_COLOR or a pipe)
irscan.exe --style             force styling even when stdout is redirected
irscan.exe --ascii             ASCII glyph fallbacks instead of box drawing
irscan.exe --severity-colour   tint HIGH red (default is strictly monochrome)
irscan.exe --width N           wrap the console view to N columns
irscan.exe --quiet             hide per-collector progress lines
irscan.exe --yara-rules PATH   extra YARA rules (file or directory, comma-separated)
irscan.exe --no-yara           skip content scanning entirely
```

## 5. Functional requirements

Each requirement is testable; the right column names the automated check.

| ID | Requirement | Verified by |
|----|-------------|-------------|
| FR-1 | Reports host identity, OS build, install date, boot time, elevation state | `report_contains_identity` |
| FR-2 | Enumerates processes: PID, PPID, image path, command line, owner, start time, signature trust | host smoke test |
| FR-3 | Enumerates services and kernel drivers with image path, start mode, account, state | host smoke test |
| FR-4 | Enumerates scheduled tasks from `%WINDIR%\System32\Tasks\**`, including hidden flag and author | `parse_task_xml_*` |
| FR-5 | Enumerates autoruns: Run/RunOnce (HKLM/HKCU + Wow6432Node), Winlogon Shell/Userinit, AppInit_DLLs, IFEO Debugger, BootExecute | `autorun_*` |
| FR-6 | Enumerates WMI event-subscription persistence | host smoke test |
| FR-7 | Enumerates TCP/UDP endpoints with owning PID, state and label for distinctive ports | `parse_network_table` |
| FR-8 | Enumerates local accounts and Administrators membership | host smoke test |
| FR-9 | Reports remote-access configuration: RDP enabled, RDP listener, Remote Assistance, WinRM, sshd, active sessions | `rdp_*` |
| FR-10 | Extracts event-log evidence: System 7045, Security 4697/4624(type 10)/4625, Defender 1006–1119, TaskScheduler 106, TerminalServices 1149 | `parse_event_xml_*` |
| FR-11 | Reports Defender state and **exclusions** (excluding a path is a classic malware move) | `defender_exclusions_*` |
| FR-12 | Reports keyboard/mouse/display device-class filter drivers (`UpperFilters`/`LowerFilters`) — where input hooking and screen-capture filter drivers register | `class_filter_*` |
| FR-13 | Flags processes/services/tasks running from user-writable locations or without a trusted signature | `is_user_writable_*`, `execution_severity_*` |
| FR-14 | Detects masquerading binaries (system-process names outside `%SystemRoot%`) | `masquerade_*` |
| FR-15 | Matches every collected string against the embedded signature database, one finding per product | `signature_*` |
| FR-16 | Reports product evidence files (AnyDesk `connection_trace.txt`, TeamViewer `Connections_incoming.txt`, …) including the remote address recorded inside them | `trace_artifact_*` |
| FR-17 | Emits severity-tagged findings and an aggregate verdict that states its own limits | `verdict_*` |
| FR-18 | Writes a UTF-8 report file and prints a console summary | host smoke test |
| FR-19 | `--json` emits a stable, documented schema | `json_schema_*` |
| FR-20 | `--watch N` reports new outbound connections with owning process | host smoke test |
| FR-21 | Never writes anywhere except the report path; refuses to follow reparse points while walking | `is_reparse_*` |
| FR-22 | Build-time signature generation is deterministic: same input, byte-identical output | `tools/check_generated.sh` |
| FR-23 | Scans the executables it already has a reason to look at with bundled YARA rules, and reports each match with the rule's own severity, the file and its size | `yara::severity_from_meta`, `yara::compile_sources`, `the_bundled_rule_file_compiles_and_contains_rules` |
| FR-24 | Accepts additional YARA rule files or directories, and isolates a rule that fails to compile instead of losing the whole scan | `a_broken_source_is_isolated_and_the_good_one_survives` |
| FR-25 | Presents a styled console view whose severity is readable in monochrome, and never depends on colour for meaning | `severity_markers_are_distinct_without_colour`, `plain_style_emits_no_escape_sequences_at_all` |
| FR-26 | Keeps the report file plain and byte-stable; the styled view is console-only | `report_rendering_is_deterministic`, `console_view_renders_every_section_and_stays_within_the_width` |
| FR-27 | Collapses structurally identical findings in the console view with an instance count, while the JSON keeps every instance | `identical_findings_collapse_into_one_entry_with_a_count`, `json_output_has_the_documented_shape` |
| FR-28 | Reports progress per collector, to stderr, so a redirected stdout still receives a clean report | `progress_is_reported_for_every_collector_including_a_failing_one` |

## 6. Quality attributes and tactics (ADD)

| Attribute | Priority | Tactic |
|-----------|----------|--------|
| **Security** | 1 | Read-only by default; no shell, ever; bounded input; no network; no dynamic loading; output sanitised for ANSI/control characters |
| **Reliability** | 2 | Every collector is fallible and isolated: one failure produces a warning, never aborts the scan. No `unwrap`/`expect`/`panic` on external data — enforced by lint |
| **Testability** | 3 | All classification, parsing and formatting is pure and unit-tested; OS access sits behind `Collector`, so logic tests need no Windows |
| **Auditability** | 4 | Every finding carries the raw evidence that produced it; severity comes from explicit, readable rules in one module |
| **Performance** | 5 | Hard caps per collector (events, files, recursion depth, bytes read); `--quick` skips the expensive ones |
| **Modifiability** | 6 | One file per collector; adding a check touches no other collector |

## 7. Security requirements

- SR-1: The tool never invokes a shell or `CreateProcess` on anything it inspects.
- SR-2: All data from the system under test is untrusted: length-capped and sanitised at every
  boundary before printing or writing.
- SR-3: Filesystem walks skip reparse points (junctions, symlinks) so a walk cannot escape its root.
- SR-4: Every FFI return value is checked; every buffer is sized from the length the API reports,
  never from a guessed constant.
- SR-5: Any future quarantine action writes only inside one fixed root with sanitised names.
- SR-6: No `unsafe` outside the `win` module.
- SR-7: `cargo clippy --all-targets -- -D warnings` and `cargo test` must both pass;
  `unsafe_op_in_unsafe_fn` and `clippy::unwrap_used` are denied crate-wide.

## 8. Interfaces

### 8.1 Text report (the artefact) and console view (the presentation)

Two renderings of the same data, deliberately kept apart:

* **`report::render_text`** writes the file. Plain ASCII, fixed section order, no ANSI
  ever. Each finding is rendered as

  ```
  [HIGH] category: title
         evidence line
      -> remediation line
  ```

  and the file ends with a `RAW DATA` appendix holding the collected tables verbatim.
  This is the artefact that gets copied to external media, hashed and pasted into a
  ticket, so its bytes must not depend on a terminal.
* **`ui::render_console`** writes the terminal view. Monochrome palette (black, grey,
  white), severity carried by a glyph and a `[ HIGH ]` chip rather than by hue,
  sections underlined with rules, evidence hung off a thin gutter, and structurally
  identical findings collapsed to one entry with an instance count.

The console view is suppressed entirely when stdout is not a TTY, when `NO_COLOR` is
set, or on `--plain`, at which point the text report is what the user sees.

### 8.2 JSON report (`--json`)

```json
{ "schema": "irscan/v1",
  "host": { "name": "...", "os": "...", "build": "...", "admin": true },
  "verdict": { "high": 0, "med": 0, "info": 0, "headline": "...", "recommendation": ["..."] },
  "findings": [ { "severity": "high", "category": "...", "title": "...",
                  "evidence": ["..."], "remediation": ["..."] } ],
  "warnings": ["..."] }
```

Stable field names; additive changes only, guarded by `json_schema_*` tests.

## 9. Acceptance criteria

- AC-1: `cargo build --release` succeeds with zero warnings.
- AC-2: `cargo clippy --all-targets -- -D warnings` is clean.
- AC-3: `cargo test` passes; every FR with a unit test above has one.
- AC-4: The release binary, run on a real Windows host, writes a report containing the identity
  section, a non-empty process list and a verdict; no panic, no truncated file.
- AC-5: Feeding a controlled process name that exists in the database produces a signature finding
  (verified by the signature unit tests and a host smoke test).
- AC-6: The report file is valid UTF-8 and contains no raw ANSI escape from any system string.
- AC-7: Regenerating the signature database twice yields identical bytes.
- AC-8: `cargo clippy --all-targets -- -D warnings` is clean and `cargo fmt --all --check`
  reports no diff.
- AC-9: `--plain`, `NO_COLOR` and a redirected stdout each produce output containing no
  ESC byte at all.
- AC-10: A syntactically broken rule file passed to `--yara-rules` costs only that file:
  the bundled rules still load and the report carries a warning naming the file.

## 10. Test plan (TDD)

- **Unit (majority)**: pure functions — path classification, masquerade detection, severity policy,
  environment expansion, private-IP classification, task-XML extraction, event-XML extraction,
  network-table parsing, signature matching, JSON rendering, verdict aggregation, sanitisation.
  Written before or alongside the implementation.
- **Integration**: each collector runs against the live host and must return `Ok` (or a typed
  warning) inside its time budget; driven by `--self-test`.
- **End-to-end**: run the release binary; assert report structure and exit code.
- **Negative**: malformed XML, over-long strings, embedded NULs, ANSI escapes, unterminated escape
  sequences; assert no panic and correct sanitisation.
