#!/bin/bash
# =====================================================================================================================
# run-3.1.sh - runs every formal model of version 3.1 and writes a summary table.
#
# Besides the six models of version 3.0 (run-all-formal.sh) it runs
#   - the three copies with the prover identifier id_P in the signed context
#       cryptoverif/nipok-idp.cv, proverif/nipok-idp.pv, proverif/nipok-e2e-idp.pv
#   - the four mutation copies of proverif/nipok-e2e.pv in proverif/mutations/
# and compares each result with the outcome expected in UNVERIFIED-3.1.md.
#
# Output, in results-3.1/ (or $OUT):
#   summary.md      one row per query: expected outcome, observed outcome, verdict, wall-clock seconds of the file
#   versions.txt    what the tools report about themselves, and the machine
#   logs/<file>.log complete output of each run
# Exit status: 0 if every query has its expected outcome; 1 if at least one differs; 2 if a tool is missing or a run
# gave no result line (the table then shows NOT RUN or NO RESULT for these rows).
#
# Usage:  cd formal && ./run-3.1.sh            (TIMEOUT=seconds per file, default 3600; OUT=directory)
# Requires proverif, cryptoverif and easycrypt as described in README.md, "Requirements".
# =====================================================================================================================
set -uo pipefail
cd "$(dirname "$0")"
OUT="${OUT:-results-3.1}"
TIMEOUT="${TIMEOUT:-3600}"
mkdir -p "$OUT/logs"
SUM="$OUT/summary.md"
differ=0; notrun=0

# --- versions and machine -------------------------------------------------------------------------------------------
{
  echo "date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "--- machine"
  uname -srm 2>/dev/null
  grep -m1 'model name' /proc/cpuinfo 2>/dev/null
  echo "cores: $(nproc 2>/dev/null)"
  grep -m1 MemTotal /proc/meminfo 2>/dev/null
  ( . /etc/os-release 2>/dev/null && echo "os: ${PRETTY_NAME:-}" )
  echo "--- opam"
  opam list --installed proverif cryptoverif easycrypt alt-ergo why3 ocaml 2>/dev/null | grep -v '^#' || echo "(opam not available)"
  echo "--- proverif (first lines of its help text)"
  proverif --help 2>&1 | head -n 3
  echo "--- cryptoverif (first lines of its help text)"
  cryptoverif -help 2>&1 | head -n 3
  echo "--- easycrypt config"
  easycrypt config 2>&1 | head -n 20
  echo "--- alt-ergo"
  alt-ergo --version 2>&1 | head -n 1
} > "$OUT/versions.txt" 2>&1

{
  echo "# Formal models of version 3.1: summary of a run"
  echo
  echo "Run of $(date -u '+%Y-%m-%d %H:%M UTC'); tool versions and machine in \`versions.txt\`, complete output in \`logs/\`."
  echo
  echo "| File | Query | Expected | Observed | Verdict | Seconds (file) |"
  echo "|---|---|---|---|---|---|"
} > "$SUM"

row() {  # <file> <query id> <expected> <observed> <seconds>
  local verdict
  case "$4" in
    "NOT RUN"|"NO RESULT"|"TIMEOUT") verdict="$4"; notrun=$((notrun+1)) ;;
    "$3") verdict="as expected" ;;
    *) verdict="DIFFERENT"; differ=$((differ+1)) ;;
  esac
  echo "| \`$1\` | $2 | $3 | $4 | $verdict | $5 |" >> "$SUM"
  printf '   %-46s %-28s expected %-18s observed %-18s %s\n' "$1" "$2" "$3" "$4" "$verdict"
}

runlog() {  # <tool> <file> [args before the file...] ; sets LOG, SECS, STATUS (0 ok, 124 timeout, 127 tool missing)
  local tool="$1" file="$2"; shift 2
  LOG="$OUT/logs/$(echo "$file" | tr '/' '_').log"; SECS="-"; STATUS=0
  if ! command -v "$tool" >/dev/null 2>&1; then STATUS=127; : > "$LOG"; return; fi
  local t0 t1
  t0=$(date +%s)
  timeout "$TIMEOUT" "$tool" "$@" "$file" > "$LOG" 2>&1; STATUS=$?
  t1=$(date +%s); SECS=$((t1 - t0))
}

observed() {  # <fixed string that identifies the RESULT line of the query> ; prints true | false | cannot be proved | ...
  local line
  if [ "$STATUS" = 127 ]; then echo "NOT RUN"; return; fi
  # lines of the form "RESULT (but ...)" or "RESULT (even ...)" are remarks on the previous query and are skipped
  line=$(grep '^RESULT [^(]' "$LOG" | grep -F -- "$1" | tail -n 1)
  if [ -z "$line" ]; then [ "$STATUS" = 124 ] && echo "TIMEOUT" || echo "NO RESULT"; return; fi
  case "$line" in
    *"is true."*) echo "true" ;;
    *"is false."*) echo "false" ;;
    *"cannot be proved"*) echo "cannot be proved" ;;
    *) echo "unrecognized" ;;
  esac
}

e2e() {  # <file> : the seven queries of the end-to-end model, each expected true
  runlog proverif "$1"
  row "$1" "S1 secrecy of x"        true "$(observed 'attacker(xPSU')" "$SECS"
  row "$1" "A1 NIPoK agreement"     true "$(observed 'BankAccepts(')" "$SECS"
  row "$1" "A2 code-token"          true "$(observed 'inj-event(TokenIssued(')" "$SECS"
  row "$1" "A3 JARM authenticity"   true "$(observed 'event(TppGotCode(')" "$SECS"
  row "$1" "A4 token integrity"     true "$(observed 'event(RsGrants(')" "$SECS"
  row "$1" "A5 consent, customer"   true "$(observed 'event(RsGrantsResource(')" "$SECS"
  row "$1" "A6 consent, account"    true "$(observed 'event(RsGrantsAccountResource(')" "$SECS"
}

nipok() {  # <file> : the two queries of the NIPoK-only model
  runlog proverif "$1"
  row "$1" "secrecy of x"           true "$(observed 'attacker(xA')" "$SECS"
  row "$1" "injective agreement"    true "$(observed 'server_accepts(')" "$SECS"
}

cv() {  # <file> : injective agreement with the bound of the paper
  local bound want='Psign(time_1, N) + 0.5 * N2^2 / |nonce|' obs
  runlog cryptoverif "$1"
  if [ "$STATUS" = 127 ]; then obs="NOT RUN"
  elif grep -q '^All queries proved' "$LOG"; then obs="proved"
  elif [ "$STATUS" = 124 ]; then obs="TIMEOUT"
  elif grep -q 'RESULT' "$LOG"; then obs="not proved"
  else obs="NO RESULT"; fi
  row "$1" "injective agreement"    proved "$obs" "$SECS"
  bound=$(grep '^RESULT Proved' "$LOG" | sed -n 's/.*up to probability //p' | tail -n 1 | tr -s ' ' | sed 's/ *$//')
  if [ "$obs" = proved ]; then
    # the bound contains "|nonce|": the bars are escaped so that they do not end the table cell
    want=${want//|/\\|}; bound=${bound//|/\\|}
    row "$1" "probability bound" "$want" "${bound:-none printed}" "$SECS"
  fi
}

echo "== ProVerif: models of version 3.0"
e2e   proverif/nipok-e2e.pv
nipok proverif/nipok.pv
runlog proverif proverif/custody-boundary.pv
row proverif/custody-boundary.pv "S2 secrecy, sealed blob disclosed" true "$(observed 'attacker(x')" "$SECS"
runlog proverif proverif/custody-fulldump.pv          # counterfactual: the attack trace is the expected outcome
row proverif/custody-fulldump.pv "S2 secrecy, key disclosed too" false "$(observed 'attacker(x')" "$SECS"

echo "== ProVerif: copies with id_P in the context"
e2e   proverif/nipok-e2e-idp.pv
nipok proverif/nipok-idp.pv

echo "== ProVerif: mutation copies of nipok-e2e.pv (every query is expected to stay true; see UNVERIFIED-3.1.md)"
e2e proverif/mutations/nipok-e2e-no-code-pkce.pv
e2e proverif/mutations/nipok-e2e-no-pkce.pv
e2e proverif/mutations/nipok-e2e-no-sig-cnf.pv
e2e proverif/mutations/nipok-e2e-no-cnf.pv

echo "== CryptoVerif"
cv cryptoverif/nipok.cv
cv cryptoverif/nipok-idp.cv

echo "== EasyCrypt"
rm -f easycrypt/SchnorrFS.eco       # an up-to-date cache makes 'easycrypt compile' return without checking any proof
runlog easycrypt easycrypt/SchnorrFS.ec compile
if [ "$STATUS" = 127 ]; then ec="NOT RUN"
elif [ "$STATUS" = 124 ]; then ec="TIMEOUT"
elif [ "$STATUS" = 0 ]; then
  if grep -Eq '^[[:space:]]*(admit|admitted)\b' easycrypt/SchnorrFS.ec; then ec="checked, but the file contains admit"; else ec="checked, no admit"; fi
else ec="failed (status $STATUS)"; fi
row easycrypt/SchnorrFS.ec "three lemmas, exit status 0" "checked, no admit" "$ec" "$SECS"

{
  echo
  echo "Queries with an outcome other than the expected one: $differ. Rows not run or without a result line: $notrun."
  echo
  echo "What each outcome means for the text of the paper is listed in \`../UNVERIFIED-3.1.md\`."
} >> "$SUM"
echo
echo "Summary: $SUM   (different: $differ, not run or no result: $notrun)"
[ "$differ" -gt 0 ] && exit 1
[ "$notrun" -gt 0 ] && exit 2
exit 0
