#!/usr/bin/env python3
"""Summarise the measurement parameters (JMH and load test) as PARAMS.md, read from the JMH JSON files and *.params.txt.

Usage: python3 c6_params_summary.py <benchmark-R1-C6> --jmh-out DIR --lt-out DIR [--blocks 1-6]
Read-only. The only environment values printed are those of the section that lists the variables passed to run-all-psu.sh
(the measurement parameters) and the effective-parameter lines whose prefix is allow-listed; lines with sensitive keywords are skipped.
The params files of the published campaign were written with Vietnamese section headers; both spellings are recognised.
"""
import argparse, json, os, re

SENS = re.compile(r"pass(word)?=|secret|pepper=|private[_ ]?key=|BEGIN [A-Z ]*PRIVATE KEY|SA_PASSWORD|apikey|api_key", re.I)
EFF = ("date:", "phase:", "tuning:", "knee-search:", "agent tuning:", "L1 sweep:", "L8 rtt-sweep:", "swap:", "knee:", "settle",
       "rate-limit", "cpu-accounting:", "verify-path:", "host-cpu", "all-containers", "watch", "netem", "rtt")
# Section headers of the *.params.txt files: the Vietnamese spellings were written by the harness version that produced
# the published data, the English ones by the current harness.
ENV_HDR = ("bi\u1ebfn m\u00f4i tr\u01b0\u1eddng", "environment variables")
EFF_HDR = ("tham s\u1ed1 hi\u1ec7u l\u1ef1c", "effective parameters")
# Fixed phrases of the effective-parameter lines as written by the harness version that produced the published data,
# with the wording of the current harness; a line that still contains Vietnamese after this is not printed.
REC_EN = (
    ('gi\u1edbi h\u1ea1n b\u1ed9 nh\u1edb docker', 'docker memory limit'),
    ('0 MiB = kh\xf4ng gi\u1edbi h\u1ea1n', '0 MiB = no limit'),
    ('docker kh\xf4ng gi\u1edbi h\u1ea1n CPU c\u1ee7a node, xem MANIFEST', 'docker does not limit the CPU of the node, see MANIFEST'),
    ('restartCount m\u1ecdi container \u1edf', 'restartCount of every container in'),
    ('memory.peak/max/oom_kill c\u1ee7a pod agent', 'memory.peak/max/oom_kill of the agent pod'),
    ('l\u1ed7i k\u1ebft n\u1ed1i k6', 'k6 connection errors'),
    ('tr\u01b0\u1edbc/sau m\u1ed7i l\u1ea7n ch\u1ea1y', 'before and after every run'),
    ('/proc/stat c\u1ee7a VM WSL', '/proc/stat of the WSL VM'),
    ('CPU c\u1ee7a k6', 'CPU of k6'),
    ('cgroup m\u1ecdi container tr\xean 3 node', 'cgroup of every container on the 3 nodes'),
    ('typeperf=kh\xf4ng c\xf3', 'typeperf=none'),
    ('auth-server d\xf9ng FIXED-BASE COMB', 'auth-server uses the FIXED-BASE COMB'),
    ('trung b\xecnh', 'mean over'),
    ('journey th\u0103m d\xf2', 'probe journey'),
    ('m\u1ed7i ms RTT', 'per ms of RTT'),
    ('t\u1ed1i \u0111a', 'at most'),
)
VI_LETTER = re.compile("[" + '\xe0\xe1\u1ea1\u1ea3\xe3\xe2\u1ea7\u1ea5\u1ead\u1ea9\u1eab\u0103\u1eb1\u1eaf\u1eb7\u1eb3\u1eb5\xe8\xe9\u1eb9\u1ebb\u1ebd\xea\u1ec1\u1ebf\u1ec7\u1ec3\u1ec5\xec\xed\u1ecb\u1ec9\u0129\xf2\xf3\u1ecd\u1ecf\xf5\xf4\u1ed3\u1ed1\u1ed9\u1ed5\u1ed7\u01a1\u1edd\u1edb\u1ee3\u1edf\u1ee1\xf9\xfa\u1ee5\u1ee7\u0169\u01b0\u1eeb\u1ee9\u1ef1\u1eed\u1eef\u1ef3\xfd\u1ef5\u1ef7\u1ef9\u0111\xc0\xc1\u1ea0\u1ea2\xc3\xc2\u1ea6\u1ea4\u1eac\u1ea8\u1eaa\u0102\u1eb0\u1eae\u1eb6\u1eb2\u1eb4\xc8\xc9\u1eb8\u1eba\u1ebc\xca\u1ec0\u1ebe\u1ec6\u1ec2\u1ec4\xcc\xcd\u1eca\u1ec8\u0128\xd2\xd3\u1ecc\u1ece\xd5\xd4\u1ed2\u1ed0\u1ed8\u1ed4\u1ed6\u01a0\u1edc\u1eda\u1ee2\u1ede\u1ee0\xd9\xda\u1ee4\u1ee6\u0168\u01af\u1eea\u1ee8\u1ef0\u1eec\u1eee\u1ef2\xdd\u1ef4\u1ef6\u1ef8\u0110' + "]")


def english(t):
    for a, b in REC_EN:
        t = t.replace(a, b)
    if VI_LETTER.search(t) or "/home/" in t:
        return t.split(":", 1)[0] + ": (see the raw params file)"
    return t


JSONS = (("main", "main/official-final.json"), ("fbc-ab (avgt)", "fbc-ab/fbc_ab_avgt.json"), ("fbc-ab (thrpt)", "fbc-ab/fbc_ab_thrpt.json"),
         ("fbc-ab (sample)", "fbc-ab/fbc_ab_sample.json"), ("argon2id-sensitivity", "argon2id-sensitivity/argon2id-sensitivity.json"),
         ("jvm-control G1", "jvm-control/G1.json"), ("jvm-control T1", "jvm-control/T1.json"), ("jvm-control T2", "jvm-control/T2.json"),
         ("jvm-control G2", "jvm-control/G2.json"))


def jmh_md(jdir):
    L = ["# JMH parameters (read from the result JSON files)", "",
         "| Step | Benchmarks | Mode | Forks | Warmup | Measurement | Threads | JMH | JVM | JVM args |", "|---|---|---|---|---|---|---|---|---|---|"]
    for lab, rel in JSONS:
        p = os.path.join(jdir, rel)
        if not os.path.isfile(p):
            continue
        d = json.load(open(p))
        if not d:
            continue
        modes = sorted({x.get("mode") for x in d})
        cfg = sorted({(x.get("forks"), x.get("warmupIterations"), x.get("warmupTime"), x.get("measurementIterations"),
                       x.get("measurementTime"), x.get("threads"), x.get("jmhVersion"), "%s %s" % (x.get("vmName"), x.get("vmVersion")),
                       " ".join(x.get("jvmArgs") or [])) for x in d}, key=str)
        for c in cfg:
            L.append("| %s | %d | %s | %s | %s × %s | %s × %s | %s | %s | %s | %s |" % (
                lab, len(d), "/".join(m for m in modes if m), c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8] or "-"))
    L += ["", "Raw parameter files of the harness (wrapper, variables passed in, jar md5): jmh/params/ of the raw data (*.params.txt, "
          "README.txt, jmh-jar.md5, jmh-jar.build.txt); environment of each step: jmh/<step>/env.txt.", ""]
    return "\n".join(L) + "\n"


def parse_params(p):
    env, eff, sec = {}, [], None
    for line in open(p, encoding="utf-8", errors="replace"):
        s = line.rstrip("\n")
        if s.startswith("## "):
            sec = ("env" if any(k in s for k in ENV_HDR) else ("eff" if any(k in s for k in EFF_HDR) else None))
            continue
        if SENS.search(s):
            continue
        t = s.strip()
        if sec == "env" and re.match(r"^[A-Z_][A-Z0-9_]*=", t):
            k, v = t.split("=", 1)
            env[k] = v
        elif sec == "eff" and t.startswith(EFF):
            eff.append(english(t))
    return env, eff


def lt_md(pdir, blocks):
    L = ["# Load-test parameters (read from loadtest/params/*.params.txt)", ""]
    E = {}
    for b in blocks:
        p = os.path.join(pdir, "block%d.params.txt" % b)
        if os.path.isfile(p):
            E["block%d" % b] = parse_params(p)
    wp = os.path.join(pdir, "wan.params.txt")
    if os.path.isfile(wp):
        E["wan"] = parse_params(wp)
    keys = []
    for k in E:
        for x in E[k][0]:
            if x not in keys:
                keys.append(x)
    skip = ("RESULTS", "JMH_JSON", "PHC_JAVA", "PHC_CP", "PHC_TOOL", "RUN_LABEL")
    cols = list(E)
    L += ["## Variables passed to run-all-psu.sh (one value means identical in every block)", "",
          "| Variable | Value |", "|---|---|"]
    for k in keys:
        if k in skip:
            continue
        vals = {c: E[c][0].get(k) for c in cols}
        bl = {c: v for c, v in vals.items() if c != "wan"}
        uniq = sorted({v for v in bl.values() if v is not None})
        if len(uniq) <= 1 and (vals.get("wan") in (None,) + tuple(uniq)):
            L.append("| %s | %s |" % (k, uniq[0] if uniq else vals.get("wan")))
        else:
            L.append("| %s | %s |" % (k, "; ".join("%s: %s" % (c, "-" if v is None else v) for c, v in vals.items())))
    L += ["", "Paths (RESULTS, JMH_JSON, PHC_*) and RUN_LABEL are omitted from the table; see the raw files.", ""]
    for c in cols:
        if E[c][1]:
            L += ["## Effective parameters recorded in %s.params.txt (main lines)" % c, "", "```"] + E[c][1] + ["```", ""]
            break   # every block used the same harness and parameters; one block is printed as an example
    if "wan" in E and E["wan"][1]:
        L += ["## Effective parameters of the WAN phase (wan.params.txt, main lines)", "", "```"] + E["wan"][1] + ["```", ""]
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("root"); ap.add_argument("--jmh-out", required=True); ap.add_argument("--lt-out", required=True)
    ap.add_argument("--blocks", default="1-6")
    a = ap.parse_args()
    if "-" in a.blocks:
        lo, hi = a.blocks.split("-"); bl = list(range(int(lo), int(hi) + 1))
    else:
        bl = [int(x) for x in a.blocks.split(",")]
    os.makedirs(a.jmh_out, exist_ok=True); os.makedirs(a.lt_out, exist_ok=True)
    open(os.path.join(a.jmh_out, "PARAMS.md"), "w", encoding="utf-8").write(jmh_md(os.path.join(a.root, "jmh")))
    open(os.path.join(a.lt_out, "PARAMS.md"), "w", encoding="utf-8").write(lt_md(os.path.join(a.root, "loadtest", "params"), bl))
    print("PARAMS.md → %s, %s" % (a.jmh_out, a.lt_out))


if __name__ == "__main__":
    main()
