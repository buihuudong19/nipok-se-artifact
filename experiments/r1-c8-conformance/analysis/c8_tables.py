#!/usr/bin/env python3
"""Tables and summary from the test-vector runs (Reviewer 1, Comment 8).

Reads the v2 test vectors, the per-vector reports of the implementations that ran them (Java elisabeth, Java
libsodium, nipok_ref.py, PyNaCl), the Table 12 data of R1-C7 (table12_c7-lifecycle.csv, probe.json) and the defaults
in the source code of the prototype, and writes:
  c8_vectors_all.csv               one row per vector: expected result and stage, result of each implementation
  c8_conformance.csv               one row per case of comment 8 (Table 13 candidate)
  table13_c8-conformance_rows.tex  LaTeX body of that table (booktabs rows, no float)
  c8_parameters.csv                parameters a bank and its customer agents share (Table 14 candidate)
  table14_c8-parameters_rows.tex   LaTeX body of that table
  c8_summary.txt                   every number above with its source
Every value comes from these inputs; nothing is typed by hand except the wording of the labels.
Exit 1 if a vector differs between an implementation and the file, if a Table 12 row is missing, or if a testbed
value of probe.json differs from the code default it should equal.

Usage:
  python3 c8_tables.py --vectors V2.json --java-elisabeth J.json [--java-libsodium JL.json] --python-ref P.json
                       [--pynacl N.json] --c7-table12 table12_c7-lifecycle.csv --c7-probe probe.json
                       --repo <testbed> --out <dir>
"""
import argparse
import csv
import json
import os
import re
import sys

VERSION = "1.1"
CASES = [  # (category in the vectors, label as worded in comment 8, short label)
    ("generation_verification", "Proof generation and verification", "Generation and verification"),
    ("invalid_proof", "Invalid-proof cases", "Invalid proofs"),
    ("malformed_context", "Malformed contexts", "Malformed contexts"),
    ("replayed_nonce", "Replayed nonces", "Replayed nonces"),
    ("mismatched_identity", "Mismatched identities", "Mismatched identities"),
    ("altered_channel_binding", "Altered channel bindings", "Altered channel bindings"),
    ("cross_endpoint_forwarding", "Cross-endpoint forwarding", "Cross-endpoint forwarding"),
    ("key_registration", "How public keys are registered", "Public-key registration"),
]
# Table 12 rows (exact labels of table12_c7-lifecycle.csv) that exercise each case through the gateway, with the short
# name used in Table 13.
E2E = {
    "generation_verification": [("Reference: valid login, one at a time", "valid login")],
    "invalid_proof": [("Forged response s (one bit flipped)", "forged s"),
                      ("Non-canonical s (s plus the group order)", "non-canonical s")],
    "malformed_context": [("Payload of 95 bytes instead of 96", "95-byte payload"),
                          ("Payload not in base64url", "payload not in base64url")],
    "replayed_nonce": [("Replayed nonce", "replayed nonce"), ("Nonce never issued", "nonce never issued"),
                       ("Expired nonce (TTL 60 s)", "expired nonce"),
                       ("One proof submitted from 4 sessions at once", "one proof from 4 sessions"),
                       ("Nonces issued before the restart: unused; already used", "nonces from before a restart")],
    "mismatched_identity": [("Another user's valid proof", "another user's proof")],
    "altered_channel_binding": [("Proof bound to another TLS channel (wrong cb)", "proof for another channel")],
    "cross_endpoint_forwarding": [("Proof for another verifier", "proof for another verifier")],
    "key_registration": [("Register an invalid public key (test vectors KV02 to KV06)", "invalid keys KV02-KV06"),
                         ("Register again while the key is active", "second registration (409)"),
                         ("Register without an onboarding token; with a wrong token", "no or wrong onboarding token")],
}
STAGE_TEX = {"decode_encoding": "decoding", "decode_length": "decoding", "noncanonical_s": "decoding ($s \\ge \\ell$)",
             "equation": "verification", "registration": "registration (400)"}
IMPLS = [("java_elisabeth", "Java, elisabeth backend (prototype verifier)"),
         ("java_libsodium", "Java, libsodium backend (prototype, optional)"),
         ("python_ref", "nipok_ref.py (pure Python, independent)"),
         ("pynacl", "libsodium via PyNaCl (independent, optional)")]


def load(path):
    if not path or not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def tex(s):
    return (s.replace("\\", "\\textbackslash{}").replace("&", "\\&").replace("%", "\\%").replace("_", "\\_")
            .replace("#", "\\#"))


def ids_range(ids):
    """['IV01','IV02','IV03','IV05'] -> 'IV01-IV03, IV05'"""
    def num(x):
        return int(re.sub(r"\D", "", x))
    ids = sorted(ids, key=num)
    out, run = [], [ids[0]] if ids else []
    for a in ids[1:]:
        if num(a) == num(run[-1]) + 1 and a[:2] == run[-1][:2]:
            run.append(a)
        else:
            out.append(run)
            run = [a]
    if run:
        out.append(run)
    return ", ".join(r[0] if len(r) == 1 else "%s-%s" % (r[0], r[-1]) for r in out)


def source_default(repo, rel, key):
    """Default of a Spring @Value("${key:default}") in a source file of the prototype."""
    p = os.path.join(repo, rel)
    if not os.path.exists(p):
        return None
    m = re.search(r"\$\{" + re.escape(key) + r":([^}]*)\}", open(p, encoding="utf-8").read())
    return m.group(1) if m else None


def main():
    ap = argparse.ArgumentParser()
    for a in ("--vectors", "--java-elisabeth", "--java-libsodium", "--python-ref", "--pynacl", "--c7-table12",
              "--c7-probe", "--repo", "--out"):
        ap.add_argument(a)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    problems = []
    vec = load(a.vectors)
    reports = {"java_elisabeth": load(a.java_elisabeth), "java_libsodium": load(a.java_libsodium),
               "python_ref": load(a.python_ref), "pynacl": load(a.pynacl)}
    for k in ("java_elisabeth", "python_ref"):
        if reports[k] is None:
            problems.append("required report missing: " + k)
    ran = {k: r for k, r in reports.items() if r is not None and r.get("status", "ok") == "ok" and "results" in r}
    skipped = [k for k, r in reports.items() if k not in ran]

    rows = [("valid", t) for t in vec["valid"]] + [("invalid", t) for t in vec["invalid"]] + \
           [("key", t) for t in vec["enrollment_keys"]]
    by_impl = {k: {r["id"]: r for r in rep["results"]} for k, rep in ran.items()}
    per_vector = []
    for kind, t in rows:
        cat = "key_registration" if kind == "key" else t.get("category")
        want = "accept" if kind == "valid" else t.get("expected", "reject")
        want_stage = None if want == "accept" else ("registration" if kind == "key" else t.get("stage"))
        line = {"id": t["id"], "category": cat, "case": t.get("case", ""), "expected": want,
                "expected_stage": want_stage or ""}
        for k in ran:
            r = by_impl[k].get(t["id"])
            if r is None:
                problems.append("%s: no result for %s" % (k, t["id"]))
                line[k] = "missing"
                continue
            line[k] = r["result"] + ("" if r.get("match") else " MISMATCH")
            if not r.get("match"):
                problems.append("%s: %s does not match the vector file" % (k, t["id"]))
        per_vector.append(line)
    for k, rep in ran.items():
        if rep.get("total") != len(rows):
            problems.append("%s: %s vectors, the file has %d" % (k, rep.get("total"), len(rows)))

    # Table 12 rows
    t12 = {}
    with open(a.c7_table12, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            t12[r["test"]] = r
    for cat, lst in E2E.items():
        for label, _ in lst:
            if label not in t12:
                problems.append("Table 12 row not found: " + label)
    scen = {}
    for s in vec.get("scenarios", []):
        scen.setdefault(s["category"], []).append(s["id"])

    conf = []
    for cat, label, short in CASES:
        vs = [l for l in per_vector if l["category"] == cat]
        n_acc = sum(1 for l in vs if l["expected"] == "accept")
        n_rej = len(vs) - n_acc
        stages = {}
        for l in vs:
            if l["expected"] == "reject":
                st = STAGE_TEX.get(l["expected_stage"], l["expected_stage"])
                stages[st] = stages.get(st, 0) + 1
        sc = scen.get(cat, [])
        e2e = E2E.get(cat, [])
        conf.append({
            "case": label, "short": short, "vectors": len(vs), "accept": n_acc, "reject": n_rej,
            "ids": ids_range([l["id"] for l in vs]) if vs else "",
            "stages": "; ".join("%s: %d" % (k, v) for k, v in stages.items()),
            "stateful_scenarios": ", ".join(sc),
            "e2e_rows": "; ".join("%s (%s)" % (lab, t12[lab]["count"]) for lab, _ in e2e if lab in t12),
            "e2e_short": "; ".join(sh for _, sh in e2e),
            "same_in": "%d/%d" % (len(ran), len(ran)) if vs and all(
                not l.get(k, "").endswith("MISMATCH") for l in vs for k in ran) else "-",
        })

    # parameters: code defaults of the prototype and the values probe.json verified on the testbed
    repo = a.repo or ""
    AS = "bank/spring-cloud/authorization-server/src/main/java/sample/psu/"
    d = {
        "verifier_id": source_default(repo, AS + "nipok/NipokConfig.java", "app.psu.nipok.verifier-id"),
        "ttl": source_default(repo, AS + "nipok/NipokChallengeStore.java", "app.psu.nipok.challenge.ttl-seconds"),
        "cap": source_default(repo, AS + "nipok/NipokChallengeStore.java", "app.psu.nipok.challenge.cap"),
        "trust_header": source_default(repo, AS + "nipok/ChannelBindingResolver.java",
                                       "app.psu.nipok.trust-forwarded-cb-header"),
        "lock_max": source_default(repo, AS + "security/LoginAttemptService.java", "app.psu.lockout.max-attempts"),
        "lock_base": source_default(repo, AS + "security/LoginAttemptService.java", "app.psu.lockout.base-lock-seconds"),
        "lock_cap": source_default(repo, AS + "security/LoginAttemptService.java", "app.psu.lockout.max-lock-seconds"),
        "onboarding_default": source_default(repo, AS + "web/OnboardingConfig.java", "app.psu.onboarding.mode"),
    }
    for k, v in d.items():
        if v is None:
            problems.append("source default not found: " + k)
    probe = load(a.c7_probe) or {}
    pc = probe.get("config", {})
    live = {"verifier_id": probe.get("verifier_id"), "ttl": pc.get("nonce_ttl_s"), "lock_max": pc.get("lock_max"),
            "lock_base": pc.get("lock_base_s"), "onboard_mode": pc.get("onboard_mode"),
            "cb_matches_expected": probe.get("extra", {}).get("cb_matches_expected"),
            "unlock_after_s": probe.get("extra", {}).get("lockout_unlock_after_s")}
    for k in ("verifier_id", "ttl", "lock_max", "lock_base"):
        if live[k] is None or str(live[k]) != str(d[k]):
            problems.append("testbed %s = %s, code default %s" % (k, live[k], d[k]))
    if live["cb_matches_expected"] is not True:
        problems.append("probe.json: the cb of the gateway certificate did not match the configured value")
    params = [
        ("Suite", "edwards25519 prime-order subgroup; SHA-512 over 4-byte length-prefixed fields; untagged challenge; "
         "nonce tags NIPoK-nonce-key-v1, NIPoK-nonce-v1", "protocol version", "verification"),
        ("Wire format", "base64url, no padding, of N || V || s (96 bytes), form field password of POST /psu/auth",
         "protocol version", "decoding"),
        ("N", "32 random bytes, hidden field nipokNonce of GET /psu/login-page; single use; TTL %s s; at most %s live"
         % (d["ttl"], d["cap"]), "authorization server", "nonce store"),
        ("id_V", "testbed '%s' (code default); deployment: the issuer identifier of the bank's authorization server"
         % d["verifier_id"], "bank; configured in each agent at enrollment", "verification"),
        ("cb", "SHA-256 of the DER leaf certificate of the bank gateway; agent: from its TLS handshake; server: "
         "configured value (forwarded header trusted: %s by default)" % d["trust_header"],
         "bank certificate; update at rotation", "verification"),
        ("id_P", "UTF-8 bytes of the username registered at the bank, no normalization", "bank account",
         "verification"),
        ("X", "32-byte canonical point of order l, one per PSU and method at each bank", "customer agent (wallet)",
         "registration (400)"),
        ("Registration", "POST /psu/register (username, method=NIPOK, publicKey), header X-Onboarding-Token; "
         "201 / 400 / 403 / 409; testbed mode %s (code default %s)" % (live["onboard_mode"], d["onboarding_default"]),
         "bank onboarding", "403 / 400 / 409"),
        ("Lockout", "%s consecutive failures, then %s s, doubling per further failure, at most %s s"
         % (d["lock_max"], d["lock_base"], d["lock_cap"]), "bank policy", "refused while locked"),
        ("TPP", "none: PAR, JARM, certificate-bound tokens and client authentication are unchanged", "-", "-"),
    ]

    # ---- outputs ---------------------------------------------------------------------------------------------
    cols = ["id", "category", "case", "expected", "expected_stage"] + list(ran)
    with open(os.path.join(a.out, "c8_vectors_all.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for l in per_vector:
            w.writerow({k: l.get(k, "") for k in cols})
    ccols = ["case", "vectors", "accept", "reject", "ids", "stages", "stateful_scenarios", "e2e_rows", "same_in"]
    with open(os.path.join(a.out, "c8_conformance.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=ccols)
        w.writeheader()
        for c in conf:
            w.writerow({k: c[k] for k in ccols})
    with open(os.path.join(a.out, "c8_parameters.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["parameter", "prototype", "set_by", "if_mismatched"])
        w.writerows(params)

    n_impl = len(ran)
    with open(os.path.join(a.out, "table13_c8-conformance_rows.tex"), "w", encoding="utf-8") as f:
        f.write("%% Table 13 body (R1-C8), written by c8_tables.py %s from %s and the reports of %d implementations\n"
                "%% (%s); end-to-end rows from table12_c7-lifecycle.csv. Do not edit by hand.\n"
                % (VERSION, os.path.basename(a.vectors), n_impl, ", ".join(ran)))
        f.write("\\begin{tabular}{@{}llll@{}}\n\\toprule\n"
                "Case of the comment & Vectors & Rejected at & End-to-end (Table~\\ref{tab:c7-lifecycle}) \\\\\n"
                "\\midrule\n")
        for c in conf:
            if c["accept"] and not c["reject"]:
                vtxt = "%d valid (%s)" % (c["accept"], c["ids"])
            elif c["accept"]:
                vtxt = "%d keys, %d valid (%s)" % (c["vectors"], c["accept"], c["ids"])
            else:
                vtxt = "%d (%s)" % (c["vectors"], c["ids"])
            if c["stateful_scenarios"]:
                vtxt += " + %d stateful" % len(c["stateful_scenarios"].split(", "))
            st = c["stages"] or "accepted"
            if c["stateful_scenarios"]:
                st += "; nonce store (stateful)"
            f.write("%s & %s & %s & %s \\\\\n" % (tex(c["short"]), tex(vtxt), st.replace("_", "\\_"),
                                                  tex(c["e2e_short"])))
        f.write("\\bottomrule\n\\end{tabular}\n")
    with open(os.path.join(a.out, "table14_c8-parameters_rows.tex"), "w", encoding="utf-8") as f:
        f.write("%% Table 14 body (R1-C8), written by c8_tables.py %s: values from the source defaults of the prototype\n"
                "%% (%s) and the testbed values verified in probe.json. Do not edit by hand.\n" % (VERSION, os.path.basename(repo.rstrip("/")) or repo))
        f.write("\\begin{tabular}{@{}p{0.13\\linewidth}p{0.47\\linewidth}p{0.2\\linewidth}p{0.12\\linewidth}@{}}\n"
                "\\toprule\nParameter & Prototype & Set by & If they differ \\\\\n\\midrule\n")
        names = {"N": "$N$", "id_V": "$\\mathrm{id}_V$", "cb": "$\\mathit{cb}$", "id_P": "$\\mathrm{id}_P$",
                 "X": "$X$"}
        for p, v, s, m in params:
            f.write("%s & %s & %s & %s \\\\\n" % (names.get(p, tex(p)), tex(v).replace("||", "$\\|$"), tex(s),
                                                  tex(m)))
        f.write("\\bottomrule\n\\end{tabular}\n")

    lines = ["R1-C8 conformance summary (c8_tables.py %s)" % VERSION, "",
             "Vectors: %s, %d valid proofs, %d invalid proofs, %d public keys, %d stateful scenarios, %d deployment rules"
             % (vec.get("name"), len(vec["valid"]), len(vec["invalid"]), len(vec["enrollment_keys"]),
                len(vec.get("scenarios", [])), len(vec.get("deployment_rules", []))),
             "Implementations that ran: %d" % n_impl]
    for k, label in IMPLS:
        if k in ran:
            r = ran[k]
            lines.append("  %-15s %s: %s/%s match (%s)" % (k, label, r.get("matching"), r.get("total"),
                                                         r.get("tool", "") + (" " + r.get("java", "") if "java" in r else "")))
        else:
            rr = reports.get(k)
            lines.append("  %-15s %s: not run (%s)" % (k, label, (rr or {}).get("reason", "no report")))
    lines += ["", "Per case of comment 8 (Table 13 candidate):"]
    for c in conf:
        lines.append("  %-28s vectors %2d (accept %d, reject %d) [%s]; stages: %s; stateful: %s; same in %s" % (
            c["short"], c["vectors"], c["accept"], c["reject"], c["ids"], c["stages"] or "-",
            c["stateful_scenarios"] or "-", c["same_in"]))
        lines.append("  %-28s end-to-end: %s" % ("", c["e2e_rows"] or "-"))
    lines += ["", "Parameters (Table 14 candidate); sources: code defaults in %s, probe.json of R1-C7" % (os.path.basename(repo.rstrip("/")) or repo)]
    for p, v, s, m in params:
        lines.append("  %-13s %s | set by: %s | if they differ: %s" % (p, v, s, m))
    lines += ["", "Testbed values verified by the R1-C7 probe: verifier_id=%s, nonce TTL=%s s, lockout=%s failures / %s s "
              "(unlocked after %s s), onboarding mode=%s, cb of the gateway certificate = configured cb: %s"
              % (live["verifier_id"], live["ttl"], live["lock_max"], live["lock_base"], live["unlock_after_s"],
                 live["onboard_mode"], live["cb_matches_expected"]), ""]
    lines.append("RESULT: " + ("PASS (%d vectors, %d implementations agree)" % (len(rows), n_impl) if not problems
                               else "FAIL\n  " + "\n  ".join(problems)))
    txt = "\n".join(lines) + "\n"
    open(os.path.join(a.out, "c8_summary.txt"), "w", encoding="utf-8").write(txt)
    print(txt)
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
