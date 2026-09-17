```
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║   ███╗   ██╗███████╗ ██████╗██████╗  ██████╗ ██████╗ ██╗███╗   ██╗║
    ║   ████╗  ██║██╔════╝██╔════╝██╔══██╗██╔═══██╗██╔══██╗██║████╗  ██║║
    ║   ██╔██╗ ██║█████╗  ██║     ██████╔╝██║   ██║██████╔╝██║██╔██╗ ██║║
    ║   ██║╚██╗██║██╔══╝  ██║     ██╔══██╗██║   ██║██╔══██╗██║██║╚██╗██║║
    ║   ██║ ╚████║███████╗╚██████╗██║  ██║╚██████╔╝██████╔╝██║██║ ╚████║║
    ║   ╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝

              ______
           .-'      '-.
          /            \
         |              |
         |,  .-.  .-.  ,|
         | )(_o/  \o_)( |
         |/     /\     \|
         (_     ^^     _)
          \__|IIIIII|__/
           | \IIIIII/ |
           \          /
            `--------`

         digital autopsy for the undead code
                    v1.2.0
              static-only · never executes
```

# NECROBIN

A colorful terminal autopsy for suspicious binaries.

NECROBIN reads **bytes on disk**. It does not load the sample as a program,
does not emulate it, and does not send the file anywhere. Hash lookups (optional)
submit a digest only.

```
  ✝  the body is on the slab
  🧿  we note what it was wearing
  📜  we copy the names it whispered
  ⚖  we write a guess — not a verdict
```

---

## Why it exists

Triage should be fast, readable, and honest.

- One file in → structured report out
- Works with the Python 3 standard library
- Optional helpers (`file`, `yara`, `capstone`, `upx`, `curl`, `ssdeep`) are
  auto-detected and skipped when missing
- Heuristic score is labeled as a heuristic. Packed clean software looks noisy
  too.

---

## Quick start

```bash
chmod +x necrobin.py
python3 necrobin.py sample.bin
python3 necrobin.py -i sample.bin
python3 necrobin.py --tips
python3 necrobin.py --version
```

Need color in a pipe?

```bash
FORCE_COLOR=1 python3 necrobin.py sample.bin | less -R
```

Hate color?

```bash
NO_COLOR=1 python3 necrobin.py sample.bin
```

---

## What it can eat

| Kind | What you get |
|---|---|
| **PE32 / PE32+** | sections, mitigations, imports/exports, imphash, overlay, Rich header, Authenticode *directory*, .NET flag, RSDS PDB, TLS callbacks, delay-load imports, exception dir, bound imports, resource tree (version / manifest / RCDATA) |
| **ELF** | class, endian, machine, interpreter, `DT_NEEDED`, section entropy |
| **APK / ZIP** | entries, DEX headers, native `.so` list, signing crumbs, permission harvest |
| **DEX** | header counts (strings / methods / classes) |
| **Java `.class`** | constant-pool strings |
| **OLE** | stream names, Word/Excel/PPT guess, VBA hint |
| **OOXML** | `word/` `xl/` `ppt/`, `vbaProject.bin` |
| **PDF** | `/JavaScript`, `/OpenAction`, `/URI`, `/EmbeddedFile`, stream count |
| **raw blob** | hashes, entropy, strings, XOR, carving |

Mach-O is identified. Deep Mach-O parsing is still thin.

---

## The autopsy, section by section

```
  ☠  OVERVIEW          hashes, entropy heatmap, toolchain guess, verdict
  🪟  PE / 🐧 ELF      structure, flags, sections
  📦  APK / 📄 docs    android + office + pdf + java
  🧿  SIGNATURES       packers, capabilities, carved MZ/ELF/DEX
  ⚗  CODE & CRYPTO    disasm, XOR, stack strings, TLS, resources, UPX
  📜  STRINGS & IOCS   urls, domains, ips, build leftovers vs real paths
  ⬡  HEX + ▦ HIST     first bytes and a byte-value heatmap
  ⚖  NOTES            why the score moved
```

### Recovery tricks

- **Entry disassembly** — Capstone if that interpreter can `import capstone`,
  else `ndisasm`, else a raw hex line that now prints the *actual* error
- **XOR 0x01–0xFF** ranked by mixed printable runs
- **Common keys** and `0xFF`-padded ASCII
- **Stack strings** from `mov [ebp/esp+disp], imm`
- **Base64** decode + re-tag as PE/ELF/ZIP/DEX/text
- **Split / defanged URLs** (`hxxp`, neighboring fragments)
- **DGA-looking domains** (high entropy, low vowels)
- **Family fingerprints** — string hits only, *not* config decryptors
- **UPX** — if the `upx` binary exists: `upx -d -o sample.unpacked`
  (writes a second file; still does not run it)
- **OEP / IAT hints** for packed stubs

### String hygiene

Compiler leftovers are not loot.

| Bucket | Example | Meaning |
|---|---|---|
| runtime path | `C:\Users\Public\payload.exe` | maybe interesting |
| build leftover | `c:\agent\_work\66\s\src\...\closeapps.cpp` | `__FILE__` / linker crumbs. Source is **not** in the binary |
| framework mutex | `Global\WixWaitForEventFail` | installer framework, not a unique implant mutex |
| PDB / RSDS | `foo.pdb` + GUID | leftover debug path |

---

## Command line

```
python3 necrobin.py [options] SAMPLE [OTHER]
```

| Flag | Effect |
|---|---|
| `-i`, `--interactive` | menu (best on a small keyboard) |
| `--compare A B` | size, hashes, entropy, histogram cosine, imphash |
| `--scan DIR` | walk a tree, rank by heuristic score |
| `--report` | colorless text autopsy |
| `--json` | full JSON dump |
| `--html` | collapsible HTML report |
| `--sarif` | SARIF 2.1 (CI) |
| `--stix` | STIX 2.1 bundle |
| `--misp` | MISP-shaped event JSON |
| `--iocs` | TSV indicators |
| `-o PATH` | output file; `-` = stdout |
| `--strings N` | also dump N strings in the live report |
| `--hex OFF:LEN` | extra hex window (`0x200:128`) |
| `--extract-dir DIR` | write overlay + carved blobs |
| `--vt` | VirusTotal *hash* lookup |
| `--bazaar` | MalwareBazaar *hash* lookup (no key) |
| `--write-yara` | starter rules → `~/.necrobin/rules.yar` |
| `--no-yara` | skip YARA even if present |
| `--no-banner` | skip the gravestone |
| `--tips` | lab notes |
| `--version` | `NECROBIN 1.2.0` |

Examples:

```bash
python3 necrobin.py payload.exe
python3 necrobin.py -i dropper.apk
python3 necrobin.py --compare v1.bin v2.bin
python3 necrobin.py --scan ./samples
python3 necrobin.py --html sample.bin -o autopsy.html
python3 necrobin.py --stix sample.bin -o iocs.stix.json
python3 necrobin.py --extract-dir ./out sample.bin
python3 necrobin.py --bazaar sample.bin
NECROBIN_VT_KEY=xxx python3 necrobin.py --vt sample.bin
```

---

## Interactive keys

```
  1  full autopsy                 8  hex dump
  2  overview / hashes            9  search strings
  3  format parser                d  disasm / XOR / stack / PE dirs
  4  signatures + caps            g  byte histogram
  5  IOCs                         x  extract overlay / carved
  6  interesting strings          e  export IOC / STIX / MISP / SARIF / HTML
  7  string dump                  y  yara
  v  VirusTotal hash              b  MalwareBazaar hash
  s  save text                    j  save JSON
  c  compare                      o  open another sample
  q  quit
```

---

## Optional organs

NECROBIN runs without these. They just add signal.

| Tool | Role |
|---|---|
| `python3` 3.7+ | required |
| `file` | `file(1)` one-liner |
| `yara` | rule hits (`NECROBIN_YARA` or `~/.necrobin/rules.yar`) |
| `ssdeep` | fuzzy hash |
| `curl` | VT / MalwareBazaar hash queries |
| `python3-capstone` / `pip install capstone` | real mnemonics at the entry point |
| `ndisasm` | disasm fallback |
| `upx` | decompress UPX stubs to `sample.unpacked` |
| `binutils` / `unzip` | nice to have next to the slab |

Same interpreter matters:

```bash
python3 -c "import capstone,sys; print(sys.executable, capstone.__version__, capstone.__file__)"
```

If that import fails, `apt install python3-capstone` or `python3 -m pip install capstone`
on **that** `python3`, not a different one.

---

## Environment

| Variable | Meaning |
|---|---|
| `NO_COLOR=1` | strip ANSI |
| `FORCE_COLOR=1` | keep color when piped |
| `NECROBIN_YARA=/path/rules.yar` | extra YARA file |
| `NECROBIN_VT_KEY` or `VT_API_KEY` | VirusTotal API key (SHA256 only) |

Starter rules:

```bash
python3 necrobin.py --write-yara
# writes ~/.necrobin/rules.yar if missing
```

---

## Scoring (read this twice)

```
   0–9    QUIET / BENIGN-LEANING
  10–24   WEAK SIGNALS
  25–44   INTERESTING
  45–69   SUSPICIOUS
  70–100  HOSTILE-LOOKING
```

It is a weighted pile of static clues: entropy, RWX sections, packer names,
TLS callbacks, PDF JS, Office VBA, XOR'd MZ headers, capability strings.

It is **not** an antivirus detection. A signed WiX custom-action DLL and a
packed loader can both look “interesting.” Read the evidence list.

---

## Exports

| Format | Flag | Use |
|---|---|---|
| text | `--report` | notes you can grep |
| JSON | `--json` | everything the object knew |
| HTML | `--html` | `<details>` sections, dark slab theme |
| SARIF 2.1 | `--sarif` | drop into CI |
| STIX 2.1 | `--stix` | file + url + ipv4 + domain objects |
| MISP-ish | `--misp` | event + attributes |
| TSV IOCs | `--iocs` | `type<TAB>value` |

Hash lookups never upload the body. Unpack never runs the unpacked file.

---

## Lab manners

```
  chmod a-x samples/*
  keep the graveyard off shared folders you actually execute from
  do not throw live samples at random websites
  packed ≠ evil, unpacked ≠ safe
```

NECROBIN will carve embedded PE/ELF/DEX and will write overlays to
`--extract-dir`. Those children are still samples.

---

## What it will not do

- run, inject, or emulate the file
- decrypt every Qakbot / Emotet / IcedID config (fingerprints only)
- rebuild a destroyed IAT (it will *hint*)
- replace Ghidra, capa, or a sandbox
- promise that Capstone is on PATH — it has to import inside *this* Python

---

## Layout

```
necrobin.py      the mortician
README.md        this stone
rules.yar        tiny starter rules (optional; --write-yara copies a set home)
```

One file is enough. Copy `necrobin.py` onto the box that holds the samples.

---

```
          *     *     *
     here lies another header
     MZ at midnight, PE at dawn
     entropy 7.4, no one mourned
          *     *     *

         stay curious
         stay careful
              — NECROBIN
```
