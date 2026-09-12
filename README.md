# IRScan

Read-only Windows endpoint triage for an **unauthorised monitoring / remote-control
agent** — the kind of software that screenshots the desktop, uploads it somewhere, and
sometimes moves the mouse on its own.

Built for a concrete incident: a second Windows 10 machine where the pointer moved
without the user, and windows opened by themselves. The suspect was either a covert
employee-monitoring agent or a RAT. Commercial monitoring products are deliberately
designed to look like ordinary software, so the tool does not rely on recognising one
file name — it checks every place such software has to leave a trace, and matches
everything it finds against a public catalogue of 323 known products.

## What it checks

| Area | Why it matters |
|------|----------------|
| Processes (path, command line, owner, signature trust, publisher) | A process running from `%APPDATA%`/`%TEMP%` without a valid signature is the single strongest static indicator available |
| Services and kernel drivers | Monitoring agents install a SYSTEM service; screen-capture drivers attach here |
| Keyboard / mouse / display **class filter drivers** | This is where input interception and capture filter drivers register — the direct answer to "the mouse moved by itself" |
| Scheduled tasks (including hidden) | The most common persistence mechanism, and hidden tasks are invisible in the Task Scheduler UI |
| Autoruns: Run/RunOnce, Winlogon, AppInit_DLLs, IFEO debugger, BootExecute | Classic injection and hijack points |
| WMI event subscriptions | Fileless persistence that survives reboots with no file on disk |
| TCP/UDP endpoints with owning PID | Who is talking to the network right now, including connections from user-writable processes |
| Event log evidence (System 7045, Security 4697/4624/4625) | A service installation record survives even when the binary is deleted |
| Defender state and **exclusions** | Excluding a path from scanning is a classic malware move |
| Product evidence files | AnyDesk `connection_trace.txt`, TeamViewer `Connections_incoming.txt` and similar often record **who connected and from where** |
| Signature database | 1,997 needles from 323 products: process names, paths, registry keys, service names, domains and **publisher names** |
| YARA content scan | The files it already has a reason to look at are scanned with bundled rules that match *combinations* of symbols - a screen-capture API set, an input-injection API set, a hidden-desktop marker - which is the only axis that survives a rename. Add your own rule directory with `--yara-rules` |

## Build

Requires Rust (MSVC toolchain). No other dependencies; the signature database is
generated at build time from vendored data.

```
cd ir-recon
cargo build --release
```

The binary is `ir-recon/target/release/irscan.exe`, and it is **self-contained**: the C
runtime is linked statically (see `.cargo/config.toml`), so no Visual C++
redistributable has to be present. Copy that one file to the machine under suspicion and
run it.

Two things to expect on a machine that has never seen the file before:

- **SmartScreen** may show "Windows protected your PC" because the binary is unsigned.
  That is expected for any newly downloaded executable; `More info` -> `Run anyway`.
- **Defender may flag the tool itself.** It enumerates processes, services, WMI
  subscriptions and event logs and reads executable contents, which is a behavioural
  profile it rightly watches for. If it quarantines `irscan.exe`, that is a false
  positive on this tool rather than a finding about the machine; allow the file
  explicitly, or run the scan from an excluded folder.

Run it from a terminal (`irscan.exe --quick`) so you can read the styled view. If you
double-click it instead, it waits for Enter before closing, so the report does not vanish
with the window; and it will offer to relaunch itself elevated, which is what full
coverage requires. It starts unelevated and offers to
relaunch itself elevated, because several checks (Security log, Prefetch, some service
metadata) need Administrator. Declining is allowed: the run continues with reduced
coverage and the report says which checks were skipped.

## The desktop application

`irscan-desktop.exe` is the same triage in a window, and it is **one file**: the front
end is embedded in the binary and the core is linked into it, so copying the single
executable to another machine is the whole installation.

```
cd desktop
cargo build --release
```

`desktop/target/release/irscan-desktop.exe` - copy it across and run it.

What it adds over the console view:

- **the same findings, readable in full** - every evidence line with room to breathe,
  filters by severity with live counts, search across titles, categories and evidence,
  and keyboard control (`/` search, `j`/`k` move, `Esc` clear);
- **"since last time"** - each scan is compared against the previous one on that machine
  and reports what appeared and what went away (see below);
- **save the report** through a native file dialog, in the same bytes the command-line
  tool writes;
- **containment** - two deliberately narrow, reversible actions with an undo record
  written before anything changes.

### Reading the same machine twice

A single scan answers "what is on this machine". A **sequence** of scans answers the
question that actually catches an intruder: *what changed*. That is the point of the
monitoring strip, and its design rests on one decision: what makes two observations "the
same thing". A process is identified by its **image name, never its pid** - a pid changes
on every restart, so pid-based comparison would report the entire process table as new on
every cycle. A connection is identified by its **remote endpoint, not its local port**.
Services, tasks, autostart entries and accounts are identified by the name or path a
reboot would have to preserve.

History is one file under `%LOCALAPPDATA%\IRScan\`, holding the previous snapshot. It is
the tool's own state, not evidence: a file this version cannot parse is discarded rather
than half-read, and a missing history is simply what the first run looks like.

### Containment, and its deliberate limits

Two automated actions: **disable a service** (start type set to disabled - the image and
its configuration are left alone) and **remove an autostart value** (its contents are
saved first). Both are typed operations, never a command line assembled from a string read
off the machine, and both write an undo record next to the report *before* they change
anything, so a crash cannot leave a change with no way back.

Disabling a scheduled task, removing a WMI consumer and ending a process are **modelled,
recorded and shown, but not automated**. They return an explicit "not implemented" message
naming what to do by hand instead. A button that appears to have worked on a machine with
a RAT is worse than no button.

## The console view

Monochrome by design: black, grey and white only. Severity is carried by typography and
glyphs (`●` HIGH, `◐` MED, `○` INFO) rather than by hue, so the output stays readable in
a log, on a projector, and to a colour-blind reader. Structurally identical findings are
collapsed into one entry with an instance count, because a single process list produces
dozens of findings that differ only in their evidence, and those buries the one that
matters. `--severity-colour` adds a single red accent if you want it.

The report **file** is a different artefact: plain, colourless, byte-stable, so two runs
can be diffed to see what changed on the machine.

## Usage

```
irscan.exe                     full scan: styled console view + plain .txt report
irscan.exe --json out.json     machine-readable report (schema in docs/spec.md)
irscan.exe --quick             skip the slow collectors (prefetch, filesystem walk)
irscan.exe --watch 120         watch new outbound connections for 120 seconds
irscan.exe --out DIR           where to write the report
irscan.exe --self-test         run each collector once and report which failed
irscan.exe --no-elevate        stay unelevated on purpose

irscan.exe --plain             never emit ANSI (also implied by NO_COLOR or a pipe)
irscan.exe --style             force styling even when stdout is redirected
irscan.exe --ascii             ASCII glyph fallbacks instead of box drawing
irscan.exe --width N           wrap the console view to N columns
irscan.exe --quiet             hide the per-collector progress lines
irscan.exe --yara-rules PATH   extra YARA rules (file or directory)
irscan.exe --no-yara           skip content scanning entirely
```

Run it from a USB stick so the report lands on the stick rather than the suspect disk.

## What this tool does NOT prove

- A clean result is **not** proof that the machine is clean. A kernel-mode rootkit, or a
  renamed agent with no registry trace, can hide from every user-mode API used here.
- It never tries to remove anything by itself. For a real RAT, no user-mode cleanup is
  complete — reinstall the OS from external media.
- Findings are heuristics with raw evidence attached. Read the evidence, not just the
  severity tag.

## Design

- **Read-only.** It writes exactly one thing: the report. It never contacts the network,
  never invokes a shell, and never executes anything it inspects.
- **Safe on a hostile host.** All data from the analysed system is length-capped and
  sanitised (ANSI/OSC escape sequences, control characters and bidirectional overrides
  are stripped) before it reaches the console or the report.
- **Honest.** The verdict states its own limits in the report itself, and the tool tells
  you when a collector failed instead of silently reporting less.

`docs/spec.md` holds the numbered requirements; `docs/architecture.md` explains the
design and the FFI safety rules. The crate denies `unwrap`, `expect` and `panic`, and
all `unsafe` lives in `src/win/`.

## Signature data and licensing

The signature database is generated by `build.rs` from
[magicsword-io/LOLRMM](https://github.com/magicsword-io/LOLRMM) (Apache-2.0), pinned to
a specific commit with SHA-256 hashes recorded in `THIRD_PARTY_NOTICES.md`. That file
also lists the reference projects in `raw/`, including two copyleft ones
(hayabusa, chainsaw) from which **no code was taken**.

This project is licensed under MIT OR Apache-2.0.
