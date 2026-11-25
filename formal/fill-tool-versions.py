#!/usr/bin/env python3
"""fill-tool-versions.py - fills the table "Tool versions and machine of the published runs" of formal/README.md and
the line "TO FILL" of easycrypt/SchnorrFS.ec from the file written by collect-versions.sh.

Usage (from formal/):  python3 fill-tool-versions.py [tool-versions-3.1.txt]
The values are copied as the tools print them; nothing is guessed. A value that the file does not contain is left as
"TO FILL" and reported, and the exit status is then 1. Run `git diff` afterwards and read the changes before committing.
"""
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "tool-versions-3.1.txt")
README = os.path.join(HERE, "README.md")
SCHNORR = os.path.join(HERE, "easycrypt", "SchnorrFS.ec")


def read(p):
    with io.open(p, encoding="utf-8") as f:
        return f.read()


def write(p, s):
    with io.open(p, "w", encoding="utf-8") as f:
        f.write(s)


def section(text, name):
    """Lines after '--- <name>' up to the next '---' or '##' header, without blank lines."""
    out, on = [], False
    for line in text.splitlines():
        if line.startswith("--- "):
            on = (line[4:].strip() == name)
            continue
        if line.startswith("## ") or line.startswith("### "):
            on = False
        if on and line.strip():
            out.append(line.strip())
    return out


def block(text, title):
    """Lines of the block '### <title>' of the timed runs."""
    out, on = [], False
    for line in text.splitlines():
        if line.startswith("### "):
            on = (line[4:].strip() == title)
            continue
        if line.startswith("## "):
            on = False
        if on:
            out.append(line.rstrip())
    return out


def machine(text):
    out, on = [], False
    for line in text.splitlines():
        if line.startswith("## "):
            on = (line.strip() == "## Machine")
            continue
        if on and line.strip():
            out.append(re.sub(r"\s+", " ", line.strip()))
    return out


def first(lines, pattern=None):
    for l in lines:
        if pattern is None or re.search(pattern, l, re.I):
            return l
    return ""


def cell(s):
    return s.replace("|", "\\|").strip()


text = read(SRC)
missing = []

proverif = first(section(text, "proverif"))
cryptoverif = first(section(text, "cryptoverif"))
ec = section(text, "easycrypt")
easycrypt = first(ec, r"git-hash|version|commit|release") or first(ec)
altergo = first(section(text, "alt-ergo"))
ocaml = first(section(text, "ocaml"))
mach = "; ".join(l for l in machine(text) if not l.startswith("running under WSL"))
if any(l.startswith("running under WSL") for l in machine(text)):
    mach += "; WSL2"
e2e = block(text, "proverif/nipok-e2e.pv")
secs = first(e2e, r"^wall-clock seconds:")
rc = first(e2e, r"^exit status:")
runtime = ""
if secs and rc.endswith(": 0"):
    runtime = secs.split(":", 1)[1].strip() + " s (one run, collect-versions.sh)"

values = {
    "| ProVerif |": proverif,
    "| CryptoVerif |": cryptoverif,
    "| EasyCrypt |": easycrypt,
    "| SMT solver(s) |": ("Alt-Ergo " + altergo) if altergo else "",
    "| OCaml switch |": ocaml,
    "| Machine of the 150 s |": mach,
    "| Measured run time of `nipok-e2e.pv` |": runtime,
}

rd = read(README)
lines = rd.split("\n")
for key, val in values.items():
    idx = [i for i, l in enumerate(lines) if l.startswith(key)]
    if len(idx) != 1:
        sys.exit(f"README.md: expected exactly one row starting with {key!r}, found {len(idx)}")
    i = idx[0]
    if not val:
        missing.append(key.strip("| ").strip())
        continue
    lines[i] = f"{key} {cell(val)} |"
rd2 = "\n".join(lines)
if not missing:
    rd2 = rd2.replace("""<!-- TO BE FILLED BY THE FIRST AUTHOR BEFORE THE RELEASE OF 3.1 (item 7 of the
     list of open actions). Do not release with this block unfilled.
     `./collect-versions.sh` writes the values to tool-versions-3.1.txt. -->""",
                      "Values written by `collect-versions.sh` (file `tool-versions-3.1.txt`) and copied by `fill-tool-versions.py`.")
write(README, rd2)

sc = read(SCHNORR)
blank = "(*    ________________________________________"
if easycrypt and blank in sc:
    i = sc.index(blank)
    j = sc.index("\n", i)
    width = j - i
    body = "(*    " + easycrypt
    if len(body) > width - 2:
        body = body[: width - 5] + "..."
    sc = sc[:i] + body.ljust(width - 2) + "*)" + sc[j:]
    k = sc.index("(*  >>> TO FILL BY THE FIRST AUTHOR BEFORE RELEASE <<<")
    m = sc.index("\n", k)
    sc = sc[:k] + sc[m + 1:]                                   # the marker line goes; the value stays under its label
    write(SCHNORR, sc)
elif not easycrypt:
    missing.append("EasyCrypt line of SchnorrFS.ec")

for k, v in values.items():
    print(f"{k.strip('| ').strip():40s} {v if v else 'NOT FOUND, left as TO FILL'}")
if missing:
    print("\nNot filled: " + ", ".join(missing) + ". Check that the tool is installed and run collect-versions.sh again.")
    sys.exit(1)
print("\nFilled. Read `git diff` before committing.")
