#!/usr/bin/env bash
# =====================================================================================================================
# run-conformance.sh - test vectors and negative cases of NIPoK-SE (Reviewer 1, Comment 8)
#
# Commands (run in the order given; "all" = check test vectors tables):
#   check     code and test files of the prototype, tools, Python, PyNaCl, libsodium, inputs from Comment 7
#   test      JUnit on the code of psu-auth-spi (Gradle): NipokCryptoTest, NipokC8Test, NipokC8VectorsTest and
#             LibsodiumEd25519GroupTest; copies the JUnit reports and the per-vector reports of the two Java backends
#             (elisabeth, libsodium) into $OUT
#   vectors   the two independent Python implementations: tools/nipok_ref.py (pure Python) and tools/nipok_nacl_check.py
#             (PyNaCl/libsodium, skipped when PyNaCl is not installed)
#   tables    the conformance table and the parameter table of the paper (candidate bodies and the bodies printed in
#             the paper), the \Cei* macros, summary, README.md, MAPPING.md and checksums of $OUT.
#             In the paper these are Table 10<!--ref:tab:c8-conformance--> and Supplementary Table S4<!--ref:tab:c8-parameters-->
#             (numbers written by docs/renumber_paper_map.py; the file names table13_*, table14_* do not change)
# The testbed (minikube) is not needed; no image is rebuilt.
#
# Variables (optional):
#   OUT       output directory (default: experiments/r1-c8-conformance/results)
#   C7_T12    lifecycle-table data of Comment 7 (default: experiments/r1-c7-security-cost-ablation/results/tables/table12_c7-lifecycle.csv)
#   C7_PROBE  probe.json of Comment 7 (raw data; default: testbed/bank/benchmark-R1-C7/e2e/probe/probe.json, or the
#             extracted raw-data archive on Zenodo)
#   PYTHON=python3   ALLOW_RUNNING=1 skips the check that no load test is running
# =====================================================================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$HERE/../.." && pwd)}"
TB="$REPO/testbed"
OUT="${OUT:-$HERE/results}"
C7_T12="${C7_T12:-$REPO/experiments/r1-c7-security-cost-ablation/results/tables/table12_c7-lifecycle.csv}"
C7_PROBE="${C7_PROBE:-$TB/bank/benchmark-R1-C7/e2e/probe/probe.json}"
PY="${PYTHON:-python3}"
SPI_DIR="$TB/bank/psu-auth-spi"
VEC_REL="testbed/bank/psu-auth-spi/src/test/resources/nipok-test-vectors-v2.json"   # relative to $REPO
VEC1_REL="testbed/bank/psu-auth-spi/src/test/resources/nipok-test-vectors-v1.json"
VEC="$REPO/$VEC_REL"
export PYTHONDONTWRITEBYTECODE=1

ok(){   printf '   [ok] %s\n' "$*"; }
warn(){ printf '   [warn] %s\n' "$*"; }
fail(){ printf '   [FAIL] %s\n' "$*"; }
hdr(){  printf '\n== %s\n' "$*"; }

SPI=bank/psu-auth-spi/src/main/java/com/openbanking/psu/auth/spi
SPT=bank/psu-auth-spi/src/test
AS=bank/spring-cloud/authorization-server/src/main/java/sample/psu
FILES=(
  "$SPI/crypto/nipok/NipokEncoding.java"
  "$SPI/crypto/nipok/NipokVerifier.java"
  "$SPI/wallet/SimulatorWalletProvider.java"
  "$AS/nipok/NipokAuthenticationProvider.java"
  "$AS/web/PsuRegistrationController.java"
  "$SPT/java/com/openbanking/psu/auth/spi/crypto/nipok/NipokC8Test.java"
  "$SPT/java/com/openbanking/psu/auth/spi/crypto/nipok/NipokC8VectorsTest.java"
  "$SPT/resources/nipok-test-vectors-v1.json"
  "$SPT/resources/nipok-test-vectors-v2.json"
)
mkdir -p "$OUT/junit" "$OUT/vectors" "$OUT/tables" || { fail "cannot create $OUT"; exit 1; }
OUT="$(cd "$OUT" && pwd)"
abs(){ if [ -e "$1" ]; then (cd "$(dirname "$1")" && printf '%s/%s' "$(pwd)" "$(basename "$1")"); else printf '%s' "$1"; fi; }
C7_T12="$(abs "$C7_T12")"; C7_PROBE="$(abs "$C7_PROBE")"
# name of libsodium.so (empty when absent); pipefail is off in the pipe because awk stops early
LIBSODIUM=$( (set +o pipefail; ldconfig -p 2>/dev/null | awk '$1 ~ /^libsodium[.]so/ {print $1; exit}') )

guard_running(){
  [ "${ALLOW_RUNNING:-0}" = 1 ] && return 0
  local r
  r=$(ps -eo pid=,args= 2>/dev/null | awk '$2 ~ /(^|\/)(ba)?sh$/ && $3 ~ /(^|\/)(run-R1C6|run-R1C7|run-all-psu)[.]sh$/' || true)
  [ -z "$r" ] || { fail "a measurement is running; wait until it ends (or set ALLOW_RUNNING=1):"; echo "$r"; return 1; }
}

cmd_check(){
  hdr "check: code and test files, tools, inputs from Comment 7"
  local bad=0 f
  for f in "${FILES[@]}"; do
    if [ -f "$TB/$f" ]; then ok "$(md5sum "$TB/$f" | cut -c1-32)  testbed/$f"; else fail "missing testbed/$f"; bad=1; fi
  done
  echo "   (md5 of the files used for the published run: docs/provenance.md)"
  [ -x "$TB/bank/gradlew" ] && ok "gradlew: testbed/bank/gradlew" || { fail "testbed/bank/gradlew not found"; bad=1; }
  command -v "$PY" >/dev/null && ok "python: $("$PY" --version 2>&1)" || { fail "$PY not found"; bad=1; }
  if "$PY" -c 'import nacl' 2>/dev/null; then ok "PyNaCl: $("$PY" -c 'import nacl; print(nacl.__version__)')"
  else warn "PyNaCl not installed: the vectors step skips the PyNaCl check (optional; python3 -m pip install --user pynacl)"; fi
  if [ -n "$LIBSODIUM" ]; then ok "$LIBSODIUM found: the Java tests also run the libsodium backend"
  else warn "libsodium.so not found: the Java tests skip the libsodium backend (optional; e.g. sudo apt install libsodium23)"; fi
  for f in "$C7_T12" "$C7_PROBE"; do
    if [ -f "$f" ]; then ok "Comment 7 input: ${f##*/} ($(md5sum "$f" | cut -c1-32))"; else fail "missing Comment 7 input: $f"; bad=1; fi
  done
  for f in "$HERE/tools/nipok_ref.py" "$HERE/tools/nipok_nacl_check.py" "$HERE/analysis/c8_tables.py" "$HERE/analysis/c8_table_layout.py"; do
    [ -f "$f" ] || { fail "missing ${f#$REPO/}"; bad=1; }
  done
  [ "$bad" = 0 ] && ok "check passed" || fail "check failed"
  return "$bad"
}

cmd_test(){
  hdr "test: JUnit on the code of psu-auth-spi (Gradle)"
  guard_running || return 1
  rm -f "$SPI_DIR"/build/c8/java-vectors-*.json
  local rc
  ( cd "$TB/bank" && ./gradlew :psu-auth-spi:cleanTest :psu-auth-spi:test --tests '*NipokCryptoTest' \
      --tests '*NipokC8Test' --tests '*NipokC8VectorsTest' --tests '*LibsodiumEd25519GroupTest' --console=plain )
  rc=$?
  rm -f "$OUT"/junit/TEST-*.xml "$OUT"/vectors/java-vectors-*.json
  cp "$SPI_DIR"/build/test-results/test/TEST-*Nipok*.xml "$SPI_DIR"/build/test-results/test/TEST-*Libsodium*.xml \
     "$OUT/junit/" 2>/dev/null
  cp "$SPI_DIR"/build/c8/java-vectors-*.json "$OUT/vectors/" 2>/dev/null
  "$PY" - "$OUT/junit" > "$OUT/junit/junit-summary.txt" <<'PY'
import glob, os, sys, xml.etree.ElementTree as ET
tot = [0, 0, 0, 0]
for f in sorted(glob.glob(os.path.join(sys.argv[1], "TEST-*.xml"))):
    r = ET.parse(f).getroot()
    n, fa, er, sk = (int(r.get(k, 0)) for k in ("tests", "failures", "errors", "skipped"))
    tot = [a + b for a, b in zip(tot, (n, fa, er, sk))]
    print("%-75s tests %2d  failures %d  errors %d  skipped %d" % (r.get("name"), n, fa, er, sk))
print("TOTAL tests %d, failures %d, errors %d, skipped %d" % tuple(tot))
PY
  cat "$OUT/junit/junit-summary.txt"
  [ -f "$OUT/vectors/java-vectors-elisabeth.json" ] || { fail "java-vectors-elisabeth.json missing (did NipokC8VectorsTest run?)"; rc=1; }
  [ -f "$OUT/vectors/java-vectors-libsodium.json" ] && ok "libsodium backend: ran" || warn "libsodium backend: skipped (no libsodium.so)"
  [ "$rc" = 0 ] && ok "test passed (Gradle rc=0)" || fail "test failed (Gradle rc=$rc)"
  return "$rc"
}

cmd_vectors(){
  hdr "vectors: two independent Python implementations (pure Python; PyNaCl/libsodium when installed)"
  local rc=0 r
  cd "$REPO" || return 1   # relative paths, so that the reports name the vector file relative to the repository
  "$PY" "$HERE/tools/nipok_ref.py" check "$VEC_REL" --report "$OUT/vectors/python-ref.json" > "$OUT/vectors/python-ref.txt"; r=$?
  tail -1 "$OUT/vectors/python-ref.txt"; [ "$r" = 0 ] || { fail "nipok_ref.py: a vector differs (see python-ref.txt)"; rc=1; }
  "$PY" "$HERE/tools/nipok_ref.py" check "$VEC1_REL" > "$OUT/vectors/python-ref-v1.txt"; r=$?
  tail -1 "$OUT/vectors/python-ref-v1.txt"; [ "$r" = 0 ] || { fail "nipok_ref.py on the v1 vectors: a vector differs"; rc=1; }
  "$PY" "$HERE/tools/nipok_nacl_check.py" "$VEC_REL" --report "$OUT/vectors/pynacl.json" > "$OUT/vectors/pynacl.txt"; r=$?
  tail -1 "$OUT/vectors/pynacl.txt"
  case "$r" in 0) ok "PyNaCl: every vector matches";; 3) warn "PyNaCl not installed: skipped";; *) fail "PyNaCl: a vector differs (see pynacl.txt)"; rc=1;; esac
  [ "$rc" = 0 ] && ok "vectors passed" || fail "vectors failed"
  return "$rc"
}

cmd_tables(){
  hdr "tables: conformance table (table13_*), parameter table (table14_*), \\Cei* macros, summary"
  local rc
  "$PY" "$HERE/analysis/c8_tables.py" --vectors "$VEC" \
    --java-elisabeth "$OUT/vectors/java-vectors-elisabeth.json" --java-libsodium "$OUT/vectors/java-vectors-libsodium.json" \
    --python-ref "$OUT/vectors/python-ref.json" --pynacl "$OUT/vectors/pynacl.json" \
    --c7-table12 "$C7_T12" --c7-probe "$C7_PROBE" --repo "$TB" --out "$OUT/tables" > "$OUT/tables/c8_tables.console.txt"
  rc=$?
  grep -E '^(Implementations|  (java|python|pynacl)|RESULT)' "$OUT/tables/c8_tables.console.txt"
  [ "$rc" = 0 ] || { fail "c8_tables.py failed (see tables/c8_summary.txt)"; return "$rc"; }
  "$PY" "$HERE/analysis/c8_table_layout.py" --c8 "$OUT" --vectors "$VEC" --c7-table12 "$C7_T12" --out "$OUT/tables/paper" \
    | sed 's/^/   /' || { fail "c8_table_layout.py failed"; return 1; }
  finish
  ok "tables passed"
}

finish(){  # README, MAPPING and checksums of $OUT
  cp -p "$HERE/analysis/templates/MAPPING.md" "$OUT/MAPPING.md"
  {
    cat "$HERE/analysis/templates/README.md"
    echo; echo "## This run"; echo
    echo "- Python: $("$PY" --version 2>&1 | cut -d' ' -f2); PyNaCl: $("$PY" -c 'import nacl; print(nacl.__version__)' 2>/dev/null || echo 'not installed')"
    echo "- Java backends of the JUnit run: $("$PY" -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("java","?"))' "$OUT/vectors/java-vectors-elisabeth.json" 2>/dev/null || echo '?')"
    echo "- Inputs: sources.md5; outputs: md5sums.txt"
  } > "$OUT/README.md"
  {
    (cd "$REPO" && md5sum "$VEC_REL" "$VEC1_REL")
    printf '%s  %s\n' "$(md5sum < "$C7_T12" | cut -c1-32)" "${C7_T12#$REPO/}"
    printf '%s  %s\n' "$(md5sum < "$C7_PROBE" | cut -c1-32)" "benchmark-R1-C7/e2e/probe/probe.json"
  } > "$OUT/sources.md5"
  ( cd "$OUT" && find . -type f ! -name md5sums.txt -print0 | sort -z | xargs -0 md5sum ) > "$OUT/md5sums.txt"
}

[ $# -gt 0 ] || { sed -n '2,24p' "$0"; exit 2; }
status=0
for c in "$@"; do
  case "$c" in
    check) cmd_check; s=$? ;;
    test) cmd_test; s=$? ;;
    vectors) cmd_vectors; s=$? ;;
    tables) cmd_tables; s=$? ;;
    all) bash "$0" check test vectors tables; s=$? ;;
    *) fail "unknown command: $c"; s=2 ;;
  esac
  if [ "$s" != 0 ]; then status=$s; fail "stopped at '$c' (rc=$s)"; break; fi
done
exit "$status"
