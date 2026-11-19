#!/usr/bin/env python3
"""Bodies of Table 13 and Table 14 as printed in the paper, and the \\Cei* macros (Reviewer 1, Comment 8).

Reads the outputs of the conformance run (per-vector reports of the implementations in vectors/, and
tables/c8_conformance.csv, tables/c8_parameters.csv written by c8_tables.py 1.1), the test vector file and the
Table 12 data of R1-C7, and writes
  table13_c8-conformance_rows.tex  conformance vectors by case (booktabs rows, no float)
  table14_c8-parameters_rows.tex   protocol parameters of a bank and its customer agents
  c8_macros.tex                    the \\Cei* macros of results.tex (R1-C8 block)
Every number comes from these inputs: counts and identifiers from the vector file and the reports (checked
against c8_conformance.csv), parameter values from c8_parameters.csv (code defaults of the prototype,
testbed values checked by c8_tables.py against probe.json). Only the wording of the labels is fixed here.
The nonce tags of the wallet are left out of the Suite row (a verifier never recomputes v, so they matter only for
reproducing TV1-TV4).
Usage:
  python3 c8_table_layout.py --c8 <results> --vectors <nipok-test-vectors-v2.json>
                             --c7-table12 <table12_c7-lifecycle.csv> --out <dir>
  python3 c8_table_layout.py ... --verify <directory of the paper tables> --results <results.tex>   (exit 1 if different)
"""
import argparse
import csv
import json
import os
import re
import sys

VERSION = "1.1"
CASES = [  # category, label in Table 13, Table 12 rows (exact labels) with the short name shown
    ("generation_verification", "Proof generation and verification",
     [("Reference: valid login, one at a time", "valid login")]),
    ("invalid_proof", "Invalid proofs",
     [("Forged response s (one bit flipped)", "forged $s$"),
      ("Non-canonical s (s plus the group order)", "non-canonical $s$")]),
    ("malformed_context", "Malformed contexts",
     [("Payload of 95 bytes instead of 96", "95-byte payload"),
      ("Payload not in base64url", "payload not in base64url")]),
    ("replayed_nonce", "Replayed nonces",
     [("Replayed nonce", "replayed nonce"), ("Nonce never issued", "nonce never issued"),
      ("Expired nonce (TTL 60 s)", "expired nonce"),
      ("One proof submitted from 4 sessions at once", "one proof from 4 sessions"),
      ("Nonces issued before the restart: unused; already used", "restart")]),
    ("mismatched_identity", "Mismatched identities", [("Another user's valid proof", "another user's proof")]),
    ("altered_channel_binding", "Altered channel bindings",
     [("Proof bound to another TLS channel (wrong cb)", "proof for another channel")]),
    ("cross_endpoint_forwarding", "Cross-endpoint forwarding",
     [("Proof for another verifier", "proof for another verifier")]),
    ("key_registration", "Public-key registration",
     [("Register an invalid public key (test vectors KV02 to KV06)", "invalid keys"),
      ("Register again while the key is active", "second key (409)"),
      ("Register without an onboarding token; with a wrong token", "no or wrong onboarding token (403)")]),
]
CSV_CASE = {"generation_verification": "Proof generation and verification", "invalid_proof": "Invalid-proof cases",
            "malformed_context": "Malformed contexts", "replayed_nonce": "Replayed nonces",
            "mismatched_identity": "Mismatched identities", "altered_channel_binding": "Altered channel bindings",
            "cross_endpoint_forwarding": "Cross-endpoint forwarding",
            "key_registration": "How public keys are registered"}
STAGE = {"decode_encoding": "decoding", "decode_length": "decoding", "noncanonical_s": "decoding ($s \\ge \\ell$)",
         "equation": "verification", "registration": "registration (400)"}
WORDS = {2: "two", 3: "three", 4: "four"}
RR = ">{\\raggedright\\arraybackslash}p{%s\\textwidth}"  # ragged-right column (array package)
REPORTS = ["java-vectors-elisabeth.json", "java-vectors-libsodium.json", "python-ref.json", "pynacl.json"]


def ids_text(ids):
    def num(x):
        return int(re.sub(r"\D", "", x))
    ids = sorted(ids, key=num)
    runs, cur = [], [ids[0]]
    for a in ids[1:]:
        if num(a) == num(cur[-1]) + 1:
            cur.append(a)
        else:
            runs.append(cur)
            cur = [a]
    runs.append(cur)
    return ", ".join(r[0] if len(r) == 1 else ("%s, %s" % (r[0], r[1]) if len(r) == 2 else "%s-%s" % (r[0], r[-1]))
                     for r in runs)


def fail(msg):
    print("c8_table_layout.py: " + msg, file=sys.stderr)
    sys.exit(1)


def build(a):
    vec = json.load(open(a.vectors, encoding="utf-8"))
    # implementations that ran and matched every vector
    total = len(vec["valid"]) + len(vec["invalid"]) + len(vec["enrollment_keys"])
    ran = []
    for f in REPORTS:
        p = os.path.join(a.c8, "vectors", f)
        if not os.path.exists(p):
            continue
        r = json.load(open(p, encoding="utf-8"))
        if r.get("status", "ok") != "ok":
            continue
        if r.get("total") != total or r.get("mismatching") != 0 or r.get("matching") != total:
            fail("%s: %s/%s vectors match, the file has %d" % (f, r.get("matching"), r.get("total"), total))
        ran.append(f)
    if "java-vectors-elisabeth.json" not in ran or "python-ref.json" not in ran:
        fail("the Java (elisabeth) and Python reports are required")
    # per-case rows from the vector file
    t12 = {r["test"]: r for r in csv.DictReader(open(a.c7_table12, encoding="utf-8"))}
    scen = {}
    for s in vec.get("scenarios", []):
        scen.setdefault(s["category"], []).append(s["id"])
    conf = {r["case"]: r for r in csv.DictReader(open(os.path.join(a.c8, "tables", "c8_conformance.csv"),
                                                      encoding="utf-8"))}
    rows = []
    for cat, label, e2e in CASES:
        if cat == "key_registration":
            vs = [(k["id"], k["expected"], "registration" if k["expected"] == "reject" else None)
                  for k in vec["enrollment_keys"]]
        else:
            vs = [(t["id"], "accept", None) for t in vec["valid"] if t.get("category") == cat] + \
                 [(t["id"], "reject", t["stage"]) for t in vec["invalid"] if t.get("category") == cat]
        acc = sum(1 for _, e, _ in vs if e == "accept")
        stages = {}
        for _, e, st in vs:
            if e == "reject":
                stages[STAGE[st]] = stages.get(STAGE[st], 0) + 1
        ids = ids_text([i for i, _, _ in vs])
        if cat == "generation_verification":
            vtxt = "%d valid proofs (%s)" % (acc, ids)
        elif cat == "key_registration":
            vtxt = "%d keys, %d valid (%s)" % (len(vs), acc, ids)
        else:
            vtxt = "%d (%s)" % (len(vs), ids)
        sc = scen.get(cat, [])
        if sc:
            vtxt += "; %d stateful scenarios (%s)" % (len(sc), ids_text(sc))
        st = "; ".join("%s: %d" % kv for kv in stages.items()) or "accepted"
        if sc:
            st += "; nonce store: %s" % ids_text(sc)
        for lab, _ in e2e:
            if lab not in t12:
                fail("Table 12 row not found: " + lab)
        # cross-check with c8_conformance.csv (written by c8_tables.py 1.1): same counts per case
        c = conf.get(CSV_CASE[cat])
        if c is None or (int(c["vectors"]), int(c["accept"]), int(c["reject"])) != (len(vs), acc, len(vs) - acc):
            fail("c8_conformance.csv disagrees with the vector file for %s" % label)
        rows.append((label, vtxt, st, "; ".join(sh for _, sh in e2e)))
    # parameters from c8_parameters.csv
    par = {r["parameter"]: r for r in csv.DictReader(open(os.path.join(a.c8, "tables", "c8_parameters.csv"),
                                                          encoding="utf-8"))}

    def grab(p, rx):
        m = re.search(rx, par[p]["prototype"])
        if not m:
            fail("c8_parameters.csv, %s: pattern %r not found" % (p, rx))
        return m.groups()
    ttl, cap = grab("N", r"TTL (\d+) s; at most (\d+) live")
    vid, = grab("id_V", r"testbed '([^']+)'")
    trust, = grab("cb", r"forwarded header trusted: (\w+) by default")
    mode, mode_def = grab("Registration", r"testbed mode (\w+) \(code default (\w+)\)")
    lmax, lbase, lcap = grab("Lockout", r"(\d+) consecutive failures, then (\d+) s, doubling per further failure, "
                                        r"at most (\d+) s")
    capf = "{:,}".format(int(cap)).replace(",", "{,}")
    prow = [
        # 1.1: the wallet's nonce tags are not listed: a verifier never recomputes v.
        ("Suite", "edwards25519 subgroup $\\mathbb{G}$; SHA-512 over 4-byte length-prefixed fields in a fixed "
                  "order; untagged challenge",
         "protocol version", "verification"),
        ("Wire format", "base64url without padding of $N \\| V \\| s$ (96~bytes), as the password field of "
                        "\\texttt{POST /psu/auth}", "protocol version", "decoding"),
        ("$N$", "32 random bytes in the login page (\\texttt{nipokNonce}); single use; TTL %s~s; at most %s "
                "live nonces" % (ttl, capf), "authorization server; returned by the agent", "nonce store"),
        ("$\\mathrm{id}_V$", "\\texttt{%s} in the testbed; in a deployment, the issuer identifier of the "
                             "authorization server" % vid, "bank; set in the agent at enrollment", "verification"),
        ("$\\mathit{cb}$", "SHA-256 of the DER leaf certificate of the bank's gateway; the agent hashes the "
                           "certificate it receives; %s" % ("the server ignores a forwarded hash header unless "
                                                             "configured to trust it" if trust == "false" else
                                                             "the server trusts a forwarded hash header by default"),
         "bank certificate; set in the server, updated at rotation",
         "verification"),
        ("$\\mathrm{id}_P$", "UTF-8 bytes of the username registered at the bank, not normalized",
         "bank account; fixed at enrollment", "verification"),
        ("$X$", "32-byte canonical encoding of a point of order $\\ell$; one per PSU and method at each bank",
         "wallet; registered once per bank", "registration (400)"),
        ("Registration", "\\texttt{POST /psu/register} (username, method, public key) behind the onboarding "
                         "gate (%s in the testbed); 201, 400, 403, 409" % ("enforced" if mode == "enforce" else "mode " + mode),
         "bank onboarding", "400, 403, 409"),
        ("Lockout", "%s consecutive failures, then %s~s, doubling per further failure, at most %s~s"
         % (lmax, lbase, lcap), "bank policy", "-"),
        ("TPP", "no NIPoK parameter; PAR, JARM, client authentication and certificate-bound tokens unchanged",
         "-", "-"),
    ]
    macros = {"CeiVecTotal": str(total), "CeiVecValid": str(len(vec["valid"])),
              "CeiVecInvalid": str(len(vec["invalid"])), "CeiVecKeys": str(len(vec["enrollment_keys"])),
              "CeiImplWord": WORDS.get(len(ran), str(len(ran)))}
    return rows, prow, macros, ran, (mode_def,)


def render(rows, prow, macros, ran):
    t13 = ["%% Table 13 body (R1-C8), written by c8_table_layout.py %s from nipok-test-vectors-v2.json, the reports of"
           % VERSION,
           "%% %d implementations (%s) and table12_c7-lifecycle.csv. Do not edit by hand."
           % (len(ran), ", ".join(r.replace(".json", "") for r in ran)),
           "\\begin{tabular}{@{}%s@{}}" % "".join(RR % w for w in ("0.17", "0.22", "0.23", "0.33")),
           "\\toprule",
           "Case & Vectors & Rejected at & Same case through the gateway \\\\",
           "\\midrule"]
    for r in rows:
        t13.append("%s & %s & %s & %s \\\\" % r)
    t13 += ["\\bottomrule", "\\end{tabular}"]
    t14 = ["%% Table 14 body (R1-C8), written by c8_table_layout.py %s from c8_parameters.csv (code defaults of the"
           % VERSION,
           "% prototype, testbed values checked against probe.json by c8_tables.py 1.1). Do not edit by hand.",
           "\\begin{tabular}{@{}%s@{}}" % "".join(RR % w for w in ("0.09", "0.5", "0.22", "0.13")),
           "\\toprule",
           "Parameter & Value in the prototype & Set by; reaches the other side & Rejected at if they differ \\\\",
           "\\midrule"]
    for r in prow:
        t14.append("%s & %s & %s & %s \\\\" % r)
    t14 += ["\\bottomrule", "\\end{tabular}"]
    mac = ["%% R1-C8 macros, written by c8_table_layout.py %s (test vectors v2 and the reports of benchmark-R1-C8)."
           % VERSION]
    for k, v in macros.items():
        mac.append("\\newcommand{\\%s}{%s}" % (k, v))
    return "\n".join(t13) + "\n", "\n".join(t14) + "\n", "\n".join(mac) + "\n"


def main():
    ap = argparse.ArgumentParser()
    for x in ("--c8", "--vectors", "--c7-table12", "--out", "--verify", "--results"):
        ap.add_argument(x)
    a = ap.parse_args()
    rows, prow, macros, ran, _ = build(a)
    t13, t14, mac = render(rows, prow, macros, ran)
    if a.verify:
        bad = 0
        for name, body in (("table13_c8-conformance_rows.tex", t13), ("table14_c8-parameters_rows.tex", t14)):
            p = os.path.join(a.verify, name)
            ok = os.path.exists(p) and open(p, encoding="utf-8").read() == body
            print("%-34s %s" % (name, "= layout output" if ok else "DIFFERENT"))
            bad += not ok
        if a.results:
            res = open(a.results, encoding="utf-8").read()
            for k, v in macros.items():
                m = re.search(r"\\newcommand\{\\%s\}\{([^}]*)\}" % k, res)
                ok = bool(m) and m.group(1) == v
                print("\\%-14s = %-6s %s" % (k, v, "ok" if ok else "results.tex has %s" % (m.group(1) if m else "none")))
                bad += not ok
        print("RESULT: " + ("PASS" if not bad else "FAIL"))
        return 0 if not bad else 1
    os.makedirs(a.out, exist_ok=True)
    open(os.path.join(a.out, "table13_c8-conformance_rows.tex"), "w", encoding="utf-8").write(t13)
    open(os.path.join(a.out, "table14_c8-parameters_rows.tex"), "w", encoding="utf-8").write(t14)
    open(os.path.join(a.out, "c8_macros.tex"), "w", encoding="utf-8").write(mac)
    print("written: table13_c8-conformance_rows.tex, table14_c8-parameters_rows.tex, c8_macros.tex (%d implementations)"
          % len(ran))
    return 0


if __name__ == "__main__":
    sys.exit(main())
