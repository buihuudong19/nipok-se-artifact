#!/usr/bin/env bash
# =====================================================================================================================
# prepare-release-3.1.sh - last commit before the tag v3.1, on the branch release-3.1.
#
# Checks that nothing is left to fill, that the numbering and the results are consistent, then writes the version and
# the date (CITATION.cff, README.md) and the section "3.1" of CHANGELOG.md (from RELEASE-NOTES-3.1.md), and commits.
# It does not push, merge or tag: those steps are on GitHub (see the message printed at the end).
#
# Usage, from the root of the repository, on release-3.1:   docs/prepare-release-3.1.sh [YYYY-MM-DD]
# (default date: today)
# =====================================================================================================================
set -euo pipefail
cd "$(dirname "$0")/.."
DATE="${1:-$(date +%F)}"
die() { printf '\n[STOP] %s\n' "$*" >&2; exit 1; }

[ "$(git rev-parse --abbrev-ref HEAD)" = "release-3.1" ] || die "check out the branch release-3.1 first"
[ -z "$(git status --porcelain)" ] || die "the working tree has uncommitted changes; commit them first"
grep -q '^version: "3.1"' CITATION.cff && die "CITATION.cff already says 3.1; nothing to do"

echo "== checks"
if grep -n "TO FILL" formal/README.md formal/easycrypt/SchnorrFS.ec; then
  die "values are missing (lines above): run  cd formal && ./collect-versions.sh --fill  and commit"
fi
python3 docs/renumber_paper_map.py --check | tail -n 1 | grep -q "in step" || die "numbering not in step"
for d in experiments/r1-c6-statistical-evaluation/results experiments/r1-c7-security-cost-ablation/results; do
  ( cd "$d" && md5sum -c --quiet md5sums.txt ) || die "md5sums.txt does not match in $d"
done
echo "nothing left to fill; numbering in step; md5sums.txt match"

echo "== version and date"
python3 - "$DATE" <<'EOF'
import io, re, sys
date = sys.argv[1]
def rw(p, f):
    s = io.open(p, encoding="utf-8").read(); t = f(s)
    if t == s: sys.exit(f"{p}: nothing replaced")
    io.open(p, "w", encoding="utf-8").write(t)
rw("CITATION.cff", lambda s: re.sub(r'^date-released: ".*"$', f'date-released: "{date}"',
                                    s.replace('version: "3.0"', 'version: "3.1"', 1), count=1, flags=re.M))
rw("README.md", lambda s: s.replace(
    "Version 3.0 (doi:10.5281/zenodo.24371175) accompanies the revised manuscript.",
    "Version 3.1 accompanies the revised manuscript; its DOI is listed under doi:10.5281/zenodo.24371174, which resolves\n"
    "to the latest version. Version 3.0 (doi:10.5281/zenodo.24371175) accompanied the first revision.", 1))
notes = io.open("RELEASE-NOTES-3.1.md", encoding="utf-8").read()
i, j = notes.index("## Changes since 3.0"), notes.index("## Before the release")
body = notes[i + len("## Changes since 3.0"):j].strip()
ch = io.open("CHANGELOG.md", encoding="utf-8").read()
head = "# Changelog\n"
if not ch.startswith(head): sys.exit("CHANGELOG.md: unexpected first line")
io.open("CHANGELOG.md", "w", encoding="utf-8").write(head + f"\n## 3.1 ({date})\n\n" + body + "\n" + ch[len(head):])
EOF
git add -A
git commit -q -m "release 3.1: version, date and changelog"
git log --oneline -1
cat <<EOF

== Done locally. Next:
  1. git push
  2. On GitHub: merge pull request #1 (release-3.1 into main).
  3. On GitHub: Releases > Draft a new release, tag v3.1 on main, title "3.1", publish.
     If the repository is linked to Zenodo, Zenodo creates the new version from this release by itself.
     If not: on Zenodo, record 10.5281/zenodo.24371175 > New version, upload the release archive, publish.
  4. Write the new version DOI as a comment on pull request #1.
EOF
