# irscan desktop UI

Three files, no build step, no framework, no dependencies:

| File | What it is |
|---|---|
| `index.html` | The shell. Every element the renderer touches, with ids. |
| `style.css` | The whole design language. Monochrome by construction. |
| `app.js` | The dictionaries, the adapter, the demo payload, and the renderer. |

## Open it standalone

Double-click `index.html`, or drag it into a browser. There is nothing to
install and nothing to serve - `file://` is fine.

A browser has no `window.__TAURI__`, so the page renders from the demo payload
instead of a real scan. That is the point of the fallback: it is how the design
gets reviewed, and how this directory can be checked without the Rust shell
being built.

The interface speaks Russian or English, decided once from `navigator.language`
at startup: a tag beginning `ru` gets Russian, everything else gets English.
There is no switch in the UI - the machine already answers the question. The
strings below are quoted in English; open the page on a Russian Windows and the
same layout reads in Russian with the same measurements.

What you should see on open:

- Header: `IRSCAN`, version, host line reading `no scan yet`, an
  `ELEVATION UNKNOWN` chip, a `Scan` button, and the two save buttons
  (disabled).
- Verdict band: three em dashes where the counts go, and the headline
  `No scan has been run yet.`
- Both panes filled with deliberate empty states - not blank space.
- "Since last time" strip: one quiet line, `Nothing to compare yet.`
- Footer: warnings count `-`, a `Raw data` toggle, and the
  "not proof of a clean machine" note, which is always on screen.

Then press **Scan**. The demo payload arrives and the same layout fills in:
`1 / 4 / 83`, eight finding groups across `HIGH`, `MED` and `INFO`, two
warnings, three raw sections. The collector names tick past in a live progress list while the
"scan" runs - that list *is* the progress indicator; there is no spinner.
The "since last time" strip fills in, and the header save buttons become
enabled.

## The demo payload

`DEMO_PAYLOAD` near the top of `app.js` is one clearly-marked constant. It is
the only data a browser can show, and it deliberately covers every branch of the
UI: a `HIGH` finding (the ● glyph and weight 600 are otherwise unreachable
without a real infection), `MED` and `INFO`, groups with `instances > 1`, several evidence lines
per finding, findings with and without remediation, collector warnings,
three raw sections, and a `delta` object (three variants; see below). If you add a state to the UI, add it here too - an
unexercised fallback is a fallback that has quietly rotted.

Its prose is translated too, and not for consistency: this payload is the whole
product for the only reader who ever sees it, a person opening a browser to find
out what the tool says. The data inside it - host name, user, paths, service
names, collector identifiers - is data and stays as it is. A real run never reads
any of it.

It also carries one hostile string on purpose. The fourth evidence line of
*"Service runs from a user-writable directory"* is

```
image=C:\Windows\Temp\<cfg name="update">\runner.exe --silent
```

An angle bracket and embedded quotes, exactly the shape of thing the real
collectors read off a machine under test. It must appear on screen **as
literal characters**. If it ever renders as an element or a broken attribute,
the renderer has started assigning markup, and that is a real vulnerability in a
tool like this.

### What the payload is not

It is not a sample of real findings, and it is not a fixture the Rust side
reads. Nothing here decides what is suspicious - severity, counts, headlines
and remediation text all come from the backend. If you find yourself adding a
rule to `app.js`, it belongs in the Rust core instead.

## Language

Every visible string this file produces goes through `t(key, params)`. There are
two flat dictionaries at the top of `app.js`, `RU` and `EN`, and one lookup
function; `{name}` in a value is replaced by `params.name`. The language is
decided once, at startup, from `navigator.language`: a tag beginning `ru` gets
`RU`, anything else gets `EN`. There is no switch in the UI, because the machine
already answers the question and a second source of truth for it could only
disagree with the shell's own locale.

The keys are stable identifiers, not the English text - a key that is also the
sentence breaks the moment the sentence is reworded, and the two languages stop
lining up.

**The backend's strings are never translated.** Finding titles, evidence lines,
file paths, raw output, collector names, service names, warnings and any
`Err(string)` are data read off a hostile machine: they appear exactly as the
core sent them. That split is deliberate and it is the whole design:

- A tool's *chrome* is a sentence a person reads, so it is translated.
- A *hash, a path or a process name* is a string somebody will search for in a
  log or paste into a ticket, so it is not.

The markup carries the same problem, and it is handled the same way: every
visible string in `index.html` is a placeholder with a `data-i18n` key (plus
`data-i18n-aria` and `data-i18n-placeholder` for attributes), and `applyI18n()`
fills them from the dictionary on boot, before the first render. The English
text between the tags is the fallback for a browser that never runs the script,
not a second translation. A bare literal in the markup is a string nobody can
find and change.

Two consequences worth knowing before you edit anything here:

- The delta **group headings** are translated, but the **search words** they
  type into the search box are not. A translated heading would type a Russian
  word into a list of English findings and return nothing; the query is keyed by
  the label's key, never by the label on screen.
- The **collector names** in the progress list stay Latin (`accounts`,
  `services`, ...), because they are what the core calls them and what someone
  would grep for. The Russian word is attached to the identifier as a tooltip
  via `collector.<name>`.

## Keyboard

| Key | Action |
|---|---|
| `/` | Focus the search box |
| `j` / `k` | Move the selection down / up, within the current filter |
| `d` | Jump to the "since last time" strip |
| `Esc` | Clear the search box |

Clicking a delta entry copies its subject to the clipboard and shows a brief
`copied` confirmation. Clicking a delta **group heading** ("services",
"processes", ...) pushes the matching word into the search box and narrows the
finding list to that kind; `Esc` clears it.

## The three delta states

The change strip ("since last time") is the one part of the UI whose whole point
is contrast, so all three of its states are reachable without a backend. Append a
query parameter to the file URL and press **Scan**:

| URL | State |
|---|---|
| `index.html?delta=first` | a first run: one quiet line, no lists, no chip |
| `index.html?delta=quiet` | a later run, nothing changed: the quietest ink on screen |
| `index.html?delta=changed` | a later run, 18 new and 3 gone, `newPresence: true` |

`?delta=changed` is the default when the parameter is absent or unknown, because
it is the state with the most to look at. The parameter is read in exactly one
place (`demoDeltaState`) and a real shell ignores it: the backend's `delta`
object always wins.

`?delta=changed` also exercises the two list caps: the `services` group carries
nine subjects, so it shows eight and an `and 1 more` line.

The strip's summary line ("18 new, 3 gone") is built in this file rather than
printed from the backend. This is the one place where a piece of the core's
wording is deliberately not used: it is a sentence a person reads on a strip
whose whole job is to be read at a glance, so it has to be translated, and a
translated backend string is impossible. The **numbers** are still the core's
numbers - only the words around them are this file's. The same rule applies to
the `?delta=first` and `?delta=quiet` lines.

Everything else the backend says is printed as it arrived, including
`verdict.headline` and `notProven`. Those two are the conclusion of the report:
this file is not the thing that gets to phrase them.

## Talking to the shell

`window.__TAURI__` is touched in exactly one place: the `Backend` object at the
top of `app.js`, which exposes three methods - `invoke(cmd, args)`,
`listen(name, handler)` and `save(opts)` - and falls back to the demo payload
when no shell is present. Everything below that object works on plain data, so the fallback
cannot rot and the renderer can be read without knowing Tauri exists.

Commands used: `app_info`, `scan`, `export_report`, `disable_service`,
`remove_autostart`. Events used: `scan://progress`.

`Backend.save(opts)` is the third and last adapter method: it calls the dialog
plugin's `save`, and resolves to `null` when there is no plugin, so the browser
fallback can show its own path box instead. A cancelled dialog resolves to
`null`, and the caller does nothing and says nothing.

## Checks

From the repository root:

```sh
# no colour literals outside :root
awk '/^:root *\\{/{r=1} /^\\}/{r=0} !r && /#[0-9a-fA-F]{3,8}\\b/' desktop/ui/style.css

# no colour-name severity anywhere
grep -RniE '\\b(red|green|amber|yellow|blue)\\b' desktop/ui/

# no eval, no markup assignment
grep -RnE '\\beval\\b|innerHTML' desktop/ui/
```

All three should print nothing.

And one for the translation: every key the markup asks for must exist in both
dictionaries, or a Russian build shows a raw key like `save.report` where a
button should be.

```sh
node -e "
const fs=require('fs');
const s=fs.readFileSync('desktop/ui/app.js','utf8');
const h=fs.readFileSync('desktop/ui/index.html','utf8');
const keys=b=>[...b.matchAll(/\"([a-z][A-Za-z0-9_.]*)\"\s*:/g)].map(m=>m[1]);
const ru=s.slice(s.indexOf('var RU = {'),s.indexOf('var EN = {'));
const en=s.slice(s.indexOf('var EN = {'),s.indexOf('var LANG ='));
const a=keys(ru).sort(), b=keys(en).sort();
const used=[...h.matchAll(/data-i18n(?:-aria|-placeholder)?=\"([^\"]+)\"/g)].map(m=>m[1]);
const miss=used.filter(k=>!a.includes(k)||!b.includes(k));
console.log(JSON.stringify(a)===JSON.stringify(b)?'keys match':'MISMATCH');
console.log(miss.length?'markup keys missing: '+miss:'markup keys ok');
"
```

Both lines should report success. The dictionaries are flat and hand-written, so
this is worth running after adding a string.

## Saving and containment

`Save report` and `Save JSON` are in the header. In a shell they open the dialog
plugin at `irscan-<host>-<stamp>.txt` (or `.json`), call `export_report` with
the current `cursor`, and show the written path with the same `copied`-style
confirmation the delta entries use. Without a dialog plugin - a plain browser -
the first save reveals a small path box over the host line and uses what it
holds; the box is anchored out of the header's flow, so its appearance moves
nothing.

The containment panel sits below the evidence of the selected finding, and only
appears when the finding's evidence contains an identifier an action can name:
a `name=<service>` line or a `Run`/`RunOnce` key path. It offers two forms,
`Disable service` and `Remove autostart`, each with a one-line consequence
sentence, a `Confirm` box that must be ticked before the button enables, and a
result line that holds both the success text (the backend's `outcome` and the
`undoPath` of the record it wrote) and any returned error.

An `Err(string)` is the **normal** answer for a name that is not on the machine.
It is shown in that result line, plainly, never as a dialog and never as a
crash. In the browser, `AcmeSupportSvc` and `AcmeAgent` succeed and anything
else returns that error, so both paths are reachable without the Rust shell.

## What is not implemented

Nothing in this directory re-reads or re-validates the undo record the backend
writes; it shows the path only. Reviewing an undo file is a shell-side job.
