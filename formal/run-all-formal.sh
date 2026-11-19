#!/bin/bash
# Runs every formal model of the artifact (three tiers). README.md lists the
# expected output. Requires proverif, cryptoverif, and easycrypt (README.md,
# "Requirements"); a tool that is not installed is skipped with a warning.
set -uo pipefail
cd "$(dirname "$0")"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
miss=0

run() {  # <tool> <args...>
  local tool="$1"; shift
  if command -v "$tool" >/dev/null 2>&1; then
    echo -e "${BLUE}> $tool $*${NC}"; "$tool" "$@"; echo
  else
    echo -e "${YELLOW}[warn] $tool is not installed; skipping ($*). See README.md, \"Requirements\".${NC}"; miss=$((miss+1))
  fi
}

echo -e "${BLUE}=== Tier 1: ProVerif (symbolic, end-to-end) ===${NC}"
run proverif proverif/nipok-e2e.pv
run proverif proverif/nipok.pv
run proverif proverif/custody-boundary.pv
# Counterfactual: here the attack trace (query false) is the expected outcome.
run proverif proverif/custody-fulldump.pv

echo -e "${BLUE}=== Tier 2: CryptoVerif (computational, composition and bound) ===${NC}"
run cryptoverif cryptoverif/nipok.cv

echo -e "${BLUE}=== Tier 3: EasyCrypt (machine-checked Sigma-protocol properties) ===${NC}"
# 'easycrypt compile' exits at once, without checking any proof, when an
# up-to-date cache (SchnorrFS.eco) lies next to the source. Delete the cache so
# that every proof is checked again.
rm -f easycrypt/SchnorrFS.eco
run easycrypt compile easycrypt/SchnorrFS.ec

[ "$miss" -gt 0 ] && echo -e "${YELLOW}($miss tool(s) not installed; see README.md, \"Requirements\")${NC}"
echo -e "${GREEN}Done. Compare the output with README.md, \"Expected results\".${NC}"
