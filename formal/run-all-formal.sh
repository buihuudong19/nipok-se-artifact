#!/bin/bash
# GAP 8 — chạy cả 3 tầng kiểm chứng hình thức (cần cài proverif/cryptoverif/easycrypt — xem README).
set -uo pipefail
cd "$(dirname "$0")"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
ok=0; miss=0

run() {  # <tool> <args...>
  local tool="$1"; shift
  if command -v "$tool" >/dev/null 2>&1; then
    echo -e "${BLUE}▶ $tool $*${NC}"; "$tool" "$@"; echo
  else
    echo -e "${YELLOW}⚠ $tool chưa cài — bỏ qua ($*). Cài: xem README §1${NC}"; miss=$((miss+1))
  fi
}

echo -e "${BLUE}═══ TẦNG 1 — ProVerif (symbolic, E2E) ═══${NC}"
run proverif proverif/nipok-e2e.pv
run proverif proverif/nipok.pv

echo -e "${BLUE}═══ TẦNG 2 — CryptoVerif (computational, composition+bound) ═══${NC}"
run cryptoverif cryptoverif/nipok.cv

echo -e "${BLUE}═══ TẦNG 3 — EasyCrypt (computational, Schnorr-FS ⇠ DL) ═══${NC}"
run easycrypt compile easycrypt/SchnorrFS.ec

[ "$miss" -gt 0 ] && echo -e "${YELLOW}($miss công cụ chưa cài — cài qua opam, xem README §1)${NC}"
echo -e "${GREEN}Xong. Đọc kết quả: README §3 (RESULT … is true / bound / [success]).${NC}"
