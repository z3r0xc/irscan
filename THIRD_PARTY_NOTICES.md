# Third-party notices

This project consumes data and reference material from other projects. Everything
listed here is either redistributed under its own licence (with attribution below)
or used as a read-only reference without copying code.

## Redistributed data

### mthcht/magicsword LOLRMM - Apache License 2.0

- Upstream: https://github.com/magicsword-io/LOLRMM
- Pinned commit: `9e46b2079cd1abb65a507f5d1d3a21fd1d737fb9`
- Licence text: `ir-recon/data/LOLRMM-LICENSE.txt` (Apache License 2.0, full text)
- What it is: a public catalogue of Remote Monitoring and Management (RMM) and
  remote-control products with their on-disk, registry, network and event-log
  artifacts, plus a certificate index of their publishers.

Vendored files and their SHA-256, so that the exact input the signature database was
generated from can always be verified:

| File | SHA-256 |
|------|---------|
| `ir-recon/data/rmm_tools.json` | `046cd8e29ef52e67704c0226af75396d8d47a4ceac2f94f2a555ec3ae7b27ae4` |
| `ir-recon/data/rmm_certificates.json` | `b85ee813e8ea9294e3ac151f7b94e966c663b8a79112f6ed1889f0ce9ed9f118` |

`ir-recon/build.rs` turns these two files into `$OUT_DIR/signatures.rs`. That file is
not checked in, so the database cannot drift from its source. Run
`tools/check_generated.sh` to verify the generation is deterministic.

## Analysed as a reference, nothing copied

### AdventDevInc/kudu - MIT

- Upstream: https://github.com/AdventDevInc/kudu
- Read at commit `f7c2557d24ea8385fb65f6ae56577b7ccb5e6894` (shallow clone in `raw/`,
  which is excluded from version control).

Kudu is a TypeScript/Electron system cleaner and scanner, and it was surveyed for
anything worth adopting. The conclusions, recorded here because they are as useful as a
reuse would have been:

- **Its publisher-trust module performs no certificate inspection at all** - it is a
  directory allow-list. It therefore adds nothing to `win/sig.rs`, which verifies both
  embedded Authenticode and `CATALOG`-signed Microsoft binaries.
- **It ships no YARA rule corpus.** `resources/yara-rules/` is gitignored and the rules
  are fetched from its cloud API at runtime, so there is no rule content to reuse. The
  pipeline design (integrity hash over sorted filenames, atomic directory swap, compile
  in bulk with a per-file fallback) informed the design of `collect/yara.rs`.
- **Its Windows coverage is a subset of irscan's.** It has no WMI subscription, IFEO,
  AppInit_DLLs, BootExecute, class-filter-driver or event-log evidence logic.
- Its elevation and command-execution layer is strictly more dangerous than this
  project's read-only, no-shell posture and was recorded as a pitfall, not a technique.

### What was adopted from it

One artefact, and it is the one that measurably improves the tool:

| Adopted | From | How |
|---------|------|-----|
| A table of 70 Windows service names with a safety rating, category and note | `src/shared/service-safety-kb.ts` | `tools/gen_known_services.py` parses the upstream TypeScript object literal and emits `ir-recon/src/known_services.rs`. The generator is deterministic (a re-run is byte-identical, checked) and its output is committed, so the build needs no Python. |

The generated table exists for one reason: a service that Windows itself ships must not
be reported merely because its image is unsigned, unreadable or absent. Those are
normal states for a system service, and reporting them buries the services that are
genuinely worth a reader's attention. The upstream MIT licence is reproduced by the
repository's `LICENSE`; the generator records the source path and upstream URL in the
generated file's header.

### What was deliberately not adopted

- `docs/cloud-yara-rules-prompt.md` holds a machine-readable inventory of about a
  hundred detection names with regular expressions. It is MIT-licensed and could be
  adapted with attribution, and it has been left alone: the document is a specification
  for rules that no longer ship with the tool it describes, so its regular expressions
  could not be validated against the behaviour they were written for. Shipping
  unvalidated detection content in a tool whose whole value is that its findings can be
  trusted is the wrong trade.
- Its `StartupApproved` registry paths were noted as a real coverage gap and are worth
  adding; they are recorded here as a follow-up rather than claimed as done.

## Reference clones (NOT redistributed)

`raw/` is excluded from version control (see `.gitignore`). It exists so that design
decisions in this tool can be traced to a real implementation rather than invented.
Nothing from this directory is compiled into, or copied into, the shipped binary.
Copyleft projects are listed precisely because code must NOT be taken from them.

| Project | Licence | Used for | Code copied |
|---------|---------|----------|-------------|
| [winsiderss/systeminformer](https://github.com/winsiderss/systeminformer) | MIT | Which native API and structure to use per artifact type | none yet |
| [last-byte/PersistenceSniper](https://github.com/last-byte/PersistenceSniper) | MIT + Commons Clause | The checklist of persistence locations to cover | none |
| [Yamato-Security/hayabusa](https://github.com/Yamato-Security/hayabusa) | **AGPL-3.0** | Reference for Windows event-log handling | **none - licence forbids it** |
| [WithSecureLabs/chainsaw](https://github.com/WithSecureLabs/chainsaw) | **GPL-3.0** | Reference for EVTX/DFIR structure | **none - licence forbids it** |
| [mthcht/LOLRMM](https://github.com/mthcht/LOLRMM) | Apache-2.0 | Superseded by the canonical upstream above | none |

### Licence decision: the copyleft restriction has been lifted

**Recorded 2026-09-12 by the project owner**, in these words: *"нам похуй на лицензию,
бери код и идею из них / продукт будет все равно открытым"*. The project is open source,
and the owner has accepted that taking copyleft code relicenses the whole project under a
copyleft licence. The previous policy - "copyleft projects are listed precisely because
code must NOT be taken from them" - no longer applies, and the table above is superseded
by the one below.

What the lift changes, and what it does not:

| | Before | After |
|---|---|---|
| Data from GPL/AGPL projects (rule corpora, hash lists, keyword sets) | not usable | usable |
| Logic from GPL/AGPL projects | not usable | usable, but still has to be ported |
| This project's licence | MIT/Apache-2.0 | follows whatever copyleft code is actually taken |

The practical limit is unchanged and is technical rather than legal: **C, PowerShell and
TypeScript cannot drop into a Rust crate.** Data can be vendored verbatim; logic has to be
re-implemented, and is only worth porting when it is small. **Prefer data over logic.**

Every item taken under the new policy must be added to the table below with its source,
licence and what was taken, so the licence obligation stays visible.

### Taken under the lifted policy

| Item | Source | Licence | What was taken |
|---|---|---|---|
| Record-sequence gap detection | [WithSecureLabs/chainsaw](https://github.com/WithSecureLabs/chainsaw) `src/analyse/gaps.rs` | GPL-3.0 | **The idea only.** No code was copied: `ir-recon/src/logaudit.rs` is an independent Rust implementation of "a hole in a sequential record id is evidence of deletion". Recorded here because the idea is theirs and attribution is cheap. |
| Remote-access service and image names | [WithSecureLabs/chainsaw](https://github.com/WithSecureLabs/chainsaw) `rules/evtx/service_installation/remote_access_tools.yml` | GPL-3.0 | **Data.** 33 service names and 39 image names, extracted by `tools/gen_remote_tools.py` into `ir-recon/src/remote_tools.rs`. No rule engine or code was taken - the YAML is parsed for two literal string lists and re-emitted in this project's own format. The generator is deterministic and `tools/check_generated.sh` proves the committed file matches its source. |
| Suspicious file names for masquerade detection | [AdventDevInc/kudu](https://github.com/AdventDevInc/kudu) `src/main/ipc/malware-scanner.ipc.ts` | MIT | **Data.** Four names added to `rules::SYSTEM_PROCESS_NAMES` (`taskmgr.exe`, `rundll32.exe`, `dllhost.exe`, `conhost.exe`). The remaining eleven were already present. Recorded because it is the source that suggested them and attribution is cheap. |

### Considered and rejected on capability, not licence

| Item | Why not |
|---|---|
| `Get-RidHijacking` in PersistenceSniper (`PersistenceSniper.psm1:1878`) | It reaches COM-hijackable registrations by escalating to SYSTEM via `ElevateTo-System` (`:457`). A read-only triage tool must not raise its own privileges to look at something; this is a design refusal and does not change with the licence. |
