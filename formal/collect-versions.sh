#!/bin/bash
# =====================================================================================================================
# collect-versions.sh - records the tool versions and the machine of the formal runs, and times the six models of
# version 3.0 once, so that the table "Tool versions and machine of the published runs" of README.md can be filled.
#
# Usage:  cd formal && ./collect-versions.sh            (TIMEOUT=seconds per file, default 1800; OUT=file)
# Output: tool-versions-3.1.txt (or $OUT). Nothing else in the tree is changed, except that the EasyCrypt cache
#         easycrypt/SchnorrFS.eco is deleted so that every proof is checked again.
# Run it on the machine and with the tools that produced the results reported in the paper.
# =====================================================================================================================
set -uo pipefail
cd "$(dirname "$0")"
OUT="${OUT:-tool-versions-3.1.txt}"
TIMEOUT="${TIMEOUT:-1800}"

has() { command -v "$1" >/dev/null 2>&1; }
now() { date +%s.%N 2>/dev/null || date +%s; }
limit() { if has timeout; then timeout "$TIMEOUT" "$@"; else "$@"; fi; }

timed() {  # <label> <tool> <args...>: runs once, prints wall-clock seconds, exit status and the result lines
  local label="$1"; shift
  local tool="$1"
  echo "### $label"
  if ! has "$tool"; then echo "not run: $tool is not installed"; echo; return; fi
  local log t0 t1 rc
  log="$(mktemp)"
  t0="$(now)"; limit "$@" >"$log" 2>&1; rc=$?; t1="$(now)"
  echo "command: $*"
  echo "exit status: $rc"
  echo "wall-clock seconds: $(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.1f", b-a}')"
  echo "result lines:"
  grep -E '^RESULT|All queries proved|Could not prove|Verification summary|is (true|false)|cannot be proved|[Pp]roved' "$log" \
    | sed 's/^/  /' | head -n 40
  echo "last lines of the output:"
  tail -n 5 "$log" | sed 's/^/  /'
  rm -f "$log"
  echo
}

{
  echo "# Tool versions and machine of the formal runs (collect-versions.sh)"
  echo "date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo
  echo "## Machine"
  uname -srm 2>/dev/null
  if [ -r /proc/cpuinfo ]; then
    grep -m1 'model name' /proc/cpuinfo
    echo "logical cores: $(nproc 2>/dev/null)"
    grep -m1 MemTotal /proc/meminfo
    ( . /etc/os-release 2>/dev/null && echo "os: ${PRETTY_NAME:-}" )
    grep -qi microsoft /proc/version 2>/dev/null && echo "running under WSL: $(tr -d '\0' </proc/version)"
  elif has sysctl; then
    echo "cpu: $(sysctl -n machdep.cpu.brand_string 2>/dev/null)"
    echo "logical cores: $(sysctl -n hw.ncpu 2>/dev/null)"
    echo "memory bytes: $(sysctl -n hw.memsize 2>/dev/null)"
    echo "os: $(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null)"
  fi
  echo
  echo "## Tools"
  echo "--- opam switch and packages"
  if has opam; then
    opam switch show 2>&1 | head -n 1
    opam list --installed proverif cryptoverif easycrypt alt-ergo why3 z3 cvc4 cvc5 ocaml 2>/dev/null | grep -v '^#'
  else
    echo "(opam not available)"
  fi
  echo "--- ocaml";       has ocaml       && ocaml -version 2>&1 | head -n 1
  echo "--- proverif";    has proverif    && proverif --help 2>&1 | head -n 2
  echo "--- cryptoverif"; has cryptoverif && cryptoverif -help 2>&1 | head -n 2
  echo "--- easycrypt";   has easycrypt   && easycrypt config 2>&1 | head -n 25
  echo "--- alt-ergo";    has alt-ergo    && alt-ergo --version 2>&1 | head -n 1
  echo "--- z3";          has z3          && z3 --version 2>&1 | head -n 1
  echo "--- cvc4/cvc5";   { has cvc5 && cvc5 --version 2>&1 | head -n 1; } ; { has cvc4 && cvc4 --version 2>&1 | head -n 1; }
  echo
  echo "## One timed run of each model of version 3.0"
  echo
  timed "proverif/nipok-e2e.pv"          proverif proverif/nipok-e2e.pv
  timed "proverif/nipok.pv"              proverif proverif/nipok.pv
  timed "proverif/custody-boundary.pv"   proverif proverif/custody-boundary.pv
  timed "proverif/custody-fulldump.pv (attack expected)" proverif proverif/custody-fulldump.pv
  timed "cryptoverif/nipok.cv"           cryptoverif cryptoverif/nipok.cv
  rm -f easycrypt/SchnorrFS.eco
  timed "easycrypt/SchnorrFS.ec"         easycrypt compile easycrypt/SchnorrFS.ec
} > "$OUT" 2>&1

case "$OUT" in /*) echo "Written: $OUT";; *) echo "Written: formal/$OUT";; esac
echo "Send this file to the corresponding author, or commit it on the branch release-3.1."
