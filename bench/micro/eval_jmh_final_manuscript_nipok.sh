#!/usr/bin/env bash
# ============================================================================
# eval_jmh_final_manuscript_nipok.sh — ĐÓNG GÓI 1-LỆNH cho phần "Evaluation"
#   của manuscript NIPoK (7 cơ chế xác thực PSU):
#       clean → build → đo JMH (cô lập) → sinh bảng + 5 đồ thị publication.
#
#   Nguồn DUY NHẤT: eval_manuscript.py   |   Dữ liệu 100% từ official-final.json
#   (không hardcode; thiếu JSON → eval tự DỪNG, không vẽ từ số cũ).
#
# DÙNG:
#   ./eval_jmh_final_manuscript_nipok.sh             # mặc định -f5 -wi8 -i10 (~25-30')
#   FORKS=2 ./eval_jmh_final_manuscript_nipok.sh     # bản nháp nhanh (~12-15', CI rộng hơn)
#   ISOLATE=0 ./eval_jmh_final_manuscript_nipok.sh   # KHÔNG dừng 3 minikube cluster (kém cô lập)
#   SKIP_MEASURE=1 ./eval_jmh_final_manuscript_nipok.sh  # KHÔNG đo lại, chỉ vẽ lại từ JSON sẵn có
#
# CÔ LẬP (mặc định BẬT — số liệu manuscript phải sạch):
#   - Dừng 3 minikube cluster (4 DB + Istio chạy nền gây nhiễu cache/scheduler).
#     SAU KHI ĐO bật lại bằng: ../../../up.sh
#   - taskset ghim JMH vào TASKSET_CPUS (mặc định 0-7) → giảm migration giữa
#     các vCPU. ⚠ i9-14900HX là CPU lai P/E-core; WSL2 ảo hóa topo nên KHÔNG
#     ghim được vào P-core vật lý — phải khai báo trong threats-to-validity.
#   - FORKS=5 mặc định: mỗi fork là 1 JVM mới → trung bình qua biến thiên
#     JIT/scheduler/core-type; quan trọng hơn tăng iteration trên CPU lai.
# ============================================================================
set -uo pipefail

# ── Cấu hình ────────────────────────────────────────────────────────────────
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BANK_DIR="$HOME/openbanking-ecosystem/bank"
FORKS="${FORKS:-5}"; WI="${WI:-8}"; IT="${IT:-10}"; SKIP_MEASURE="${SKIP_MEASURE:-0}"
ISOLATE="${ISOLATE:-1}"; TASKSET_CPUS="${TASKSET_CPUS:-0-7}"
OUTDIR="$DIR/results/2-ket qua do jmh voi 6 ky thuat"; mkdir -p "$OUTDIR"
JSON="$OUTDIR/official-final.json"
LOG="$OUTDIR/run.log"
BENCHES="NipokBenchmark|MtlsCertBenchmark|PrivateKeyJwtBenchmark|EdDsaAuthBenchmark|SchnorrBenchmark|MlDsaAuthBenchmark|Argon2Benchmark"
# 10 figs = 5 (NIPoK verify NORMAL / Straus) + 5 (NIPoK verify FBC / fixed-base comb, hậu tố _fbc).
# CHỈ verify của NIPoK khác giữa 2 bộ; 6 cơ chế còn lại y hệt (cùng JSON, chỉ đổi cột verify NIPoK).
OUTS=(tables_manuscript.md fig1_verify_logbar.png fig2_pareto.png fig3_grouped.png
      fig4_radar.png fig4.1_radar.png
      tables_manuscript_fbc.md fig1_verify_logbar_fbc.png fig2_pareto_fbc.png fig3_grouped_fbc.png
      fig4_radar_fbc.png fig4.1_radar_fbc.png official-final.json)

# ── Log helpers ─────────────────────────────────────────────────────────────
say(){ printf '\n\033[1;36m═══ %s\033[0m\n' "$*"; }
ok(){  printf '   \033[32m✔ %s\033[0m\n' "$*"; }
warn(){ printf '   \033[33m⚠ %s\033[0m\n' "$*"; }
die(){ printf '\n\033[31m✗ LỖI: %s\033[0m\n' "$*" >&2; exit 1; }

START=$(date +%s)
cd "$DIR" || die "không vào được $DIR"

# ── [0] Tiền đề ─────────────────────────────────────────────────────────────
say "[0] Tiền đề: JDK 24 (ML-DSA built-in) + thư viện vẽ + publish SPI vào mavenLocal"
if java -version 2>&1 | grep -qE 'version "24'; then ok "JDK 24"; else warn "JDK KHÔNG phải 24 — ML-DSA có thể lỗi"; fi
if python3 -c "import matplotlib, seaborn, numpy" 2>/dev/null; then
  ok "matplotlib / seaborn / numpy đã có"
else
  printf '   … cài thư viện vẽ\n'
  pip install matplotlib seaborn numpy --break-system-packages -q || die "pip install thất bại"
  ok "đã cài matplotlib / seaborn / numpy"
fi
( cd "$BANK_DIR" && ./gradlew :psu-auth-spi:publishToMavenLocal -q ) || die "publish SPI thất bại"
ok "SPI publish (psu-auth-spi → mavenLocal)"

# ── [1] Xóa data + chart cũ ─────────────────────────────────────────────────
say "[1] XÓA toàn bộ data + chart cũ (trong \"$OUTDIR\")"
rm -f "$OUTDIR"/fig*.png "$OUTDIR"/tables_manuscript*.md
if [ "$SKIP_MEASURE" = 1 ]; then
  warn "SKIP_MEASURE=1 → GIỮ JSON sẵn có (vẽ lại, không đo)"
else
  rm -f "$OUTDIR"/*.json "$OUTDIR"/*.log
  ok "đã xóa PNG + tables + JSON cũ trong thư mục kết quả"
fi
[ "$SKIP_MEASURE" = 1 ] && ok "đã xóa PNG + tables (giữ JSON)"

if [ "$SKIP_MEASURE" = 1 ]; then
  # ── [2-4] Bỏ qua build/đo ──────────────────────────────────────────────────
  say "[2-4] BỎ QUA build + đo (SKIP_MEASURE=1)"
  [ -f "$JSON" ] || die "SKIP_MEASURE=1 nhưng không thấy $JSON — bỏ SKIP_MEASURE để đo lại"
  ok "dùng JSON sẵn có: $JSON"
else
  # ── [2] Build jmhJar sạch ───────────────────────────────────────────────────
  say "[2] BUILD lại JMH uber-jar (sạch)"
  ./gradlew clean jmhJar --no-daemon -q || die "build jmhJar thất bại"
  JAR=$(ls build/libs/*-jmh.jar 2>/dev/null | head -1)
  [ -n "$JAR" ] || die "không thấy build/libs/*-jmh.jar"
  ok "jmhJar: $JAR"

  # ── [2.5] CÔ LẬP THẬT: dừng clusters + ghi nhận môi trường ─────────────────
  say "[2.5] Cô lập: dừng minikube clusters + taskset $TASKSET_CPUS (ISOLATE=$ISOLATE)"
  STOPPED_PROFILES=()
  if [ "$ISOLATE" = 1 ]; then
    for p in bank-cluster-profile tpp-cluster-profile customer-cluster-profile; do
      if minikube status -p "$p" 2>/dev/null | grep -q "host: Running"; then
        printf '   ⏹ minikube stop -p %s ...\n' "$p"
        minikube stop -p "$p" >/dev/null 2>&1 && STOPPED_PROFILES+=("$p")
      fi
    done
    [ "${#STOPPED_PROFILES[@]}" -gt 0 ] \
      && ok "đã dừng: ${STOPPED_PROFILES[*]} — BẬT LẠI sau khi đo: ../../../up.sh" \
      || ok "không có cluster nào đang chạy"
  else
    warn "ISOLATE=0 — đo với cluster đang chạy nền (KHÔNG khuyến nghị cho số manuscript)"
  fi
  # Bằng chứng môi trường đo (đính kèm results/ cho reviewer)
  { echo "date: $(date -Iseconds)"
    echo "jdk : $(java -version 2>&1 | head -1)"
    echo "cpu : $(grep 'model name' /proc/cpuinfo | head -1 | sed 's/.*: //') ($(nproc) vCPU WSL2 — topo ảo hóa, hybrid P/E do Windows xếp)"
    echo "isolate: ISOLATE=$ISOLATE taskset=$TASKSET_CPUS forks=$FORKS clusters_stopped: ${STOPPED_PROFILES[*]:-none}"
    echo "swap: $(awk '/SwapTotal/{print $2" kB"}' /proc/meminfo) (khuyến nghị swapoff -a trước khi đo)"
  } > "$OUTDIR/env.txt"
  ok "ghi môi trường đo → $OUTDIR/env.txt"

  # ── [3] Đo JMH chính thức (cô lập) ──────────────────────────────────────────
  say "[3] ĐO JMH (-f$FORKS -wi$WI -i$IT, backend elisabeth) — taskset $TASKSET_CPUS"
  printf '   … đang đo (~25-30 phút với -f5; theo dõi: tail -f %s)\n   ' "$LOG"
  taskset -c "$TASKSET_CPUS" java --enable-native-access=ALL-UNNAMED -jar "$JAR" \
    -f "$FORKS" -wi "$WI" -i "$IT" -tu us -prof gc \
    -p group=elisabeth -p shaProvider=default -p sigProvider=elisabeth -p backend=sunjce \
    -rf json -rff "$JSON" "$BENCHES" > "$LOG" 2>&1 &
  JMH_PID=$!
  while kill -0 "$JMH_PID" 2>/dev/null; do printf '.'; sleep 30; done
  printf '\n'
  wait "$JMH_PID" || die "JMH chạy lỗi (xem $LOG)"

  # ── [4] Xác nhận đo hoàn tất ────────────────────────────────────────────────
  say "[4] Xác nhận đo hoàn tất"
  grep -q 'Run complete' "$LOG" || die "JMH chưa 'Run complete' (xem $LOG)"
  [ -f "$JSON" ] || die "không sinh được $JSON"
  ok "JMH Run complete → $(basename "$JSON")"
fi

# ── [5] Sinh bảng + đồ thị: HAI BỘ (NIPoK verify NORMAL vs FIXED-BASE COMB) ──────────────────
# CÙNG official-final.json (đã chứa cả verify_server LẪN verify_server_prepared của NipokBenchmark);
# chỉ đổi cột verify của NIPoK — 6 cơ chế khác giữ nguyên ⟹ 2×5 = 10 figs.
say "[5a] SINH bộ NORMAL (NIPoK verify = Straus, verify cũ) — fig1..fig4.1 + tables_manuscript.md"
# JMH_CONFIG = cấu hình đo THẬT → in lên suptitle (hết lỗi hardcode '-f2' mô tả sai phương pháp).
OUT_DIR="$OUTDIR" JSON_PATH="$JSON" \
NIPOK_VERIFY=verify_server FIG_SUFFIX="" JMH_CONFIG="-f$FORKS -wi$WI -i$IT" python3 eval_manuscript.py \
  || die "eval_manuscript.py (normal) lỗi (thiếu JSON / guard no-hardcode?)"
ok "bộ NORMAL: 5 charts + tables_manuscript.md"

# FAIR-BASELINE: FBC áp cho CẢ 3 cơ chế edwards25519 (NIPoK + Schnorr-IZK + Pure-EdDSA);
# JWT/mTLS/ML-DSA/Password giữ nguyên (not applicable).
say "[5b] SINH bộ FIXED-BASE COMB (verify FBC: NIPoK+Schnorr-IZK+Pure-EdDSA) — fig*_fbc + tables_manuscript_fbc.md"
OUT_DIR="$OUTDIR" JSON_PATH="$JSON" \
NIPOK_VERIFY=verify_server_prepared FIG_SUFFIX="_fbc" JMH_CONFIG="-f$FORKS -wi$WI -i$IT" python3 eval_manuscript.py \
  || die "eval_manuscript.py (fbc) lỗi — kiểm JSON có 'verify_server_prepared' cho Nipok/Schnorr/EdDsa chưa?"
ok "bộ FBC: 5 charts (_fbc) + tables_manuscript_fbc.md"

# ── [6] Hiển thị đường dẫn kết quả ──────────────────────────────────────────
DUR=$(( $(date +%s) - START ))
say "[6] HOÀN TẤT (${DUR}s) — ĐƯỜNG DẪN KẾT QUẢ"
miss=0
for f in "${OUTS[@]}"; do
  if [ -f "$OUTDIR/$f" ]; then printf '   \033[32m✔\033[0m %s\n' "$OUTDIR/$f"; else printf '   \033[31m✗ THIẾU\033[0m %s\n' "$f"; miss=1; fi
done
[ "$miss" = 0 ] && printf '\n\033[1;32m✓ Gói "Evaluation" manuscript NIPoK sẵn sàng.\033[0m\n' \
                || die "có file kết quả bị thiếu — xem log phía trên"
