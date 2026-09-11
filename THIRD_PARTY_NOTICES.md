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

### Why the copyleft entries matter

`hayabusa` (AGPL-3.0) and `chainsaw` (GPL-3.0) are excellent work and were read for
approach only. Incorporating their code into this MIT/Apache-2.0 project would
relicense the whole binary under a copyleft licence. They are therefore listed as
references with an explicit "no code copied" marker, and any future contribution that
draws on them must either stay out of the build or change this project's licence
first.
