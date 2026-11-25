#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""renumber_paper_map.py - keeps the table, figure and section numbers of the documentation equal to the manuscript.

One file holds the correspondence: docs/numbering.json. For every object of the paper that the package refers to
it gives the LaTeX label of the manuscript, the document that prints it (main text or supplementary material), its
printed number, the name the object has in the file names, scripts and generated reports of this package, and the
files behind it. The documentation files listed under "targets" in numbering.json never carry a number of their
own: every reference is followed by an invisible marker that names the label,

    Table 6<!--ref:tab:lt-efficiency-->          full form, rewritten as "<kind> <number>"; an object of the
                                                 supplementary material is written "Supplementary <kind> <number>"
    Tables 6<!--ref:tab:lt-efficiency n--> ...   number only (for lists and ranges; the words around it are fixed)

and this script rewrites the text in front of each marker from numbering.json. It also rewrites the block between
<!--numbering-table:begin--> and <!--numbering-table:end--> of docs/paper-map.md (the correspondence between the
names used inside the package and the numbers of the manuscript) and the checksum lines of the rewritten files in
the md5sums.txt of their results directory.

Usage (from anywhere; paths in numbering.json are relative to the repository root):

    docs/renumber_paper_map.py --aux main_rev.aux --supp-aux supplementary.aux
        reads the printed number of every label from the .aux files of a finished LaTeX build of the manuscript
        (a label is looked up in both files; the file that defines it decides "main" or "supplementary"),
        updates numbering.json, then rewrites the target files. Give the build identification with --source,
        e.g. --source "revised manuscript, build of 2026-11-28".

    docs/renumber_paper_map.py
        rewrites the target files from numbering.json as it stands (after editing a number by hand).

    docs/renumber_paper_map.py --check
        changes nothing; exits with status 1 if a target file is not in step with numbering.json, if a marker names
        an unknown label, or if a target file contains a table, figure or section number without a marker.

A label that the manuscript no longer defines is reported and stops the run before any file is written: remove the
object from numbering.json and from the target files, or give it its new label. Python 3.8 or later, standard
library only.
"""
import argparse
import hashlib
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
NUMBERING = os.path.join(HERE, "numbering.json")

NUM = r"S?[0-9]+(?:\.[0-9]+)*"
KINDS = r"Table|Figure|Section|Theorem|Algorithm|Remark"
MARK = re.compile(r"(?P<full>(?:Supplementary\s+)?(?:%s)\s+%s)<!--ref:(?P<k1>[^ >]+)-->"
                  r"|(?P<num>%s)<!--ref:(?P<k2>[^ >]+) n-->" % (KINDS, NUM, NUM))
ANY_MARK = re.compile(r"<!--ref:([^ >]+)(?: n)?-->")
# a number that looks like a reference to the paper and has no marker behind it
BARE = re.compile(r"(?:Supplementary\s+)?\b(?:%s)s?\s+%s" % (KINDS, NUM))
BLOCK = re.compile(r"(<!--numbering-table:begin-->\n).*?(<!--numbering-table:end-->)", re.S)


def read(path):
    with io.open(path, encoding="utf-8") as f:
        return f.read()


def write(path, text):
    with io.open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def load():
    data = json.loads(read(NUMBERING))
    objs = {}
    for o in data["objects"]:
        for field in ("label", "kind", "document", "number"):
            if not o.get(field):
                sys.exit("numbering.json: object without '%s': %r" % (field, o))
        if o["document"] not in ("main", "supplementary"):
            sys.exit("numbering.json: %s: document must be 'main' or 'supplementary'" % o["label"])
        if o["label"] in objs:
            sys.exit("numbering.json: label listed twice: %s" % o["label"])
        objs[o["label"]] = o
    return data, objs


def aux_labels(path):
    """label -> printed number, from the \\newlabel lines of a LaTeX .aux file (hyperref form or plain form)."""
    out = {}
    pat = re.compile(r"\\newlabel\{([^}]+)\}\{\{((?:[^{}]|\{[^{}]*\})*)\}")
    with io.open(path, encoding="latin-1") as f:
        for line in f:
            m = pat.match(line)
            if m and not m.group(1).endswith("@cref"):
                out[m.group(1)] = re.sub(r"[{}]", "", m.group(2)).strip()
    return out


def refresh(data, objs, aux_main, aux_supp, source):
    main = aux_labels(aux_main)
    supp = aux_labels(aux_supp) if aux_supp else {}
    missing, changed = [], []
    for label, o in objs.items():
        in_main, in_supp = label in main, label in supp
        if in_main and in_supp:
            sys.exit("label defined in both .aux files: %s" % label)
        if not in_main and not in_supp:
            missing.append(label)
            continue
        doc = "main" if in_main else "supplementary"
        num = main[label] if in_main else supp[label]
        if not re.fullmatch(NUM, num):
            sys.exit("%s: printed number %r is not of the form 12, 6.2.2 or S3" % (label, num))
        if (o["document"], o["number"]) != (doc, num):
            changed.append("%-28s %s %s -> %s %s" % (label, o["document"], o["number"], doc, num))
            o["document"], o["number"] = doc, num
    if missing:
        sys.exit("not defined in the given .aux file(s) (nothing was written):\n  " + "\n  ".join(missing)
                 + "\nRemove these objects from numbering.json and from the target files, or give them their new label."
                 + ("" if aux_supp else "\n(no --supp-aux was given)"))
    data["source"] = source or data.get("source", "")
    return changed


def phrase(o, number_only=False):
    if number_only:
        return o["number"]
    return ("Supplementary " if o["document"] == "supplementary" else "") + o["kind"] + " " + o["number"]


def numbering_table(data):
    objs_in_order = data["objects"]
    rows = ["Numbers of the manuscript read from: %s." % (data.get("source") or "(not recorded)"), "",
            "| Name in the package (file names, scripts, generated reports) | Manuscript | Label | Files |",
            "|---|---|---|---|"]
    for o in objs_in_order:
        if not o.get("package_name"):
            continue
        files = ", ".join("`%s`" % f for f in o.get("files", [])) or "-"
        rows.append("| %s | %s | `%s` | %s |" % (o["package_name"], phrase(o), o["label"], files))
    return "\n".join(rows) + "\n"


def render(text, objs, path, problems):
    def one(m):
        key = m.group("k1") or m.group("k2")
        if key not in objs:
            problems.append("%s: marker names an unknown label: %s" % (path, key))
            return m.group(0)
        if m.group("full") is not None:
            return "%s<!--ref:%s-->" % (phrase(objs[key]), key)
        return "%s<!--ref:%s n-->" % (phrase(objs[key], True), key)
    out = MARK.sub(one, text)
    n_marks, n_done = len(ANY_MARK.findall(out)), len(MARK.findall(out))
    if n_marks != n_done:
        problems.append("%s: %d marker(s) without a reference of the expected form in front (expected "
                        "'<kind> <number>' before <!--ref:label--> or '<number>' before <!--ref:label n-->)"
                        % (path, n_marks - n_done))
    return out


def bare_numbers(text):
    """References to the paper that carry no marker. The correspondence block is generated, so it is skipped,
    and so are code spans and the left column of the block (names used inside the package)."""
    body = BLOCK.sub("", text)
    body = re.sub(r"`[^`\n]*`", "", body)
    return [m.group(0) for m in BARE.finditer(body) if not body.startswith("<!--ref:", m.end())]


def md5_update(repo, relpath, problems, check):
    """results/<...>/md5sums.txt lists every file of a results directory; keep the line of a rewritten file in step."""
    d = os.path.dirname(os.path.join(repo, relpath))
    sums = os.path.join(d, "md5sums.txt")
    if not os.path.isfile(sums):
        return False
    name = "./" + os.path.basename(relpath)
    with open(os.path.join(repo, relpath), "rb") as f:
        digest = hashlib.md5(f.read()).hexdigest()
    lines = read(sums).split("\n")
    hit = [i for i, ln in enumerate(lines) if ln.endswith("  " + name)]
    if len(hit) != 1:
        problems.append("%s: expected one line for %s, found %d" % (os.path.relpath(sums, repo), name, len(hit)))
        return False
    new = "%s  %s" % (digest, name)
    if lines[hit[0]] == new:
        return False
    if not check:
        lines[hit[0]] = new
        write(sums, "\n".join(lines))
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--aux", help=".aux file of the main text; refreshes the numbers of numbering.json")
    ap.add_argument("--supp-aux", help=".aux file of the supplementary material")
    ap.add_argument("--source", help="identification of the build the .aux files come from (stored in numbering.json)")
    ap.add_argument("--check", action="store_true", help="write nothing; status 1 if anything is out of step")
    ap.add_argument("--repo", default=REPO, help=argparse.SUPPRESS)
    a = ap.parse_args()
    if a.supp_aux and not a.aux:
        sys.exit("--supp-aux needs --aux")

    data, objs = load()
    stale_json = False
    if a.aux:
        changed = refresh(data, objs, a.aux, a.supp_aux, a.source)
        for c in changed:
            print("number changed: " + c)
        stale_json = bool(changed) or (a.source is not None and a.source != json.loads(read(NUMBERING)).get("source"))
        if not changed:
            print("numbering.json agrees with the .aux file(s): %d labels" % len(objs))

    problems, out_of_step, plan = [], [], []
    for rel in data["targets"]:
        path = os.path.join(a.repo, rel)
        if not os.path.isfile(path):
            problems.append("target file not found: %s" % rel)
            continue
        old = read(path)
        new = render(old, objs, rel, problems)
        if BLOCK.search(new):
            new = BLOCK.sub(lambda m: m.group(1) + numbering_table(data) + m.group(2), new)
        for b in bare_numbers(new):
            problems.append("%s: number without a marker: %r" % (rel, b))
        plan.append((rel, path, old, new))
        if new != old:
            out_of_step.append(rel)

    if problems:
        print("\n".join("PROBLEM  " + p for p in problems))
        sys.exit(1)                                   # nothing has been written
    if a.check:
        md5_stale = [rel for rel, _, old, new in plan if new == old and md5_update(a.repo, rel, problems, True)]
        for rel in out_of_step:
            print("OUT OF STEP  %s" % rel)
        for rel in md5_stale:
            print("OUT OF STEP  md5sums.txt line of %s" % rel)
        if stale_json:
            print("OUT OF STEP  docs/numbering.json (numbers differ from the .aux file(s))")
        bad = bool(out_of_step or md5_stale or stale_json or problems)
        print("check: %d target files, %d markers, %s" % (
            len(plan), sum(len(ANY_MARK.findall(new)) for _, _, _, new in plan), "NOT in step" if bad else "in step"))
        sys.exit(1 if bad else 0)

    if a.aux:
        write(NUMBERING, json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    for rel, path, old, new in plan:
        if new != old:
            write(path, new)
        sums = md5_update(a.repo, rel, problems, False)
        print("%-9s %s%s" % ("rewritten" if new != old else "unchanged", rel, "  (+ md5sums.txt)" if sums else ""))
    if problems:
        print("\n".join("PROBLEM  " + p for p in problems))
        sys.exit(1)


if __name__ == "__main__":
    main()
