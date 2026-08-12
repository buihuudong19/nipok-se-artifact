#!/bin/bash
# ============================================================
# shutdown.sh — Dừng an toàn TOÀN BỘ hệ thống (3 cluster + tunnel) bằng 1 LỆNH.
#               Đây là phép ĐẢO NGƯỢC của up.sh.
#
#   ./shutdown.sh            # STOP (mặc định, NHẸ): giữ cluster ở trạng thái stopped.
#                            #   Pair hoàn hảo với `./up.sh` (reconcile) — khởi động lại nhanh,
#                            #   KHÔNG mất disk. ⚠ Vault inmem mất config + mongo mất data khi
#                            #   stop (up.sh tự re-setup + re-import).
#   ./shutdown.sh --delete   # DELETE (NẶNG): `minikube delete` cả 3 cluster, giải phóng disk.
#                            #   ⚠ Lần sau phải chạy lại pipeline tạo cluster (02-create-clusters…)
#                            #   và IP cluster đổi → cập nhật hostAlias (02-deploy-customer-agent.sh).
#
# THỨ TỰ DỪNG = ĐẢO của up.sh start (bank→tpp→customer):
#   tunnel/port-forward → customer → tpp → bank
#   (customer phụ thuộc tpp/bank nên dừng customer TRƯỚC.)
#
# Loopback 127.0.0.2:80 (customer) / 127.0.0.3:80 (tpp) là docker port-mapping NẰM TRONG container
# minikube → TỰ MẤT khi cluster stop, không cần dọn tay.
#
# Tunnel: `minikube tunnel` (user) sinh tiến trình con `sudo ssh … -L 443/80/…` (root) giữ
# 127.0.0.1:443. SIGTERM parent để minikube tự dọn ssh con; còn sót thì sudo pkill (sẽ hỏi mật khẩu).
# ============================================================
set -uo pipefail
GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
BANK=bank-cluster-profile; TPP=tpp-cluster-profile; CUST=customer-cluster-profile
DELETE=false
[ "${1:-}" = "--delete" ] && DELETE=true
ACTION=stop; $DELETE && ACTION=delete

# ── [1/4] Dừng tunnel + ssh-forward + port-forward còn sót ──────────────────────────
echo -e "${BLUE}[1/4] Dừng tunnel / port-forward${NC}"
if pgrep -f 'minikube tunnel' >/dev/null 2>&1; then
  pkill -TERM -f 'minikube tunnel' 2>/dev/null && echo "  → SIGTERM minikube tunnel (để nó tự dọn route + ssh con)"
  for _ in 1 2 3 4 5; do pgrep -f 'minikube tunnel' >/dev/null 2>&1 || break; sleep 1; done
  pkill -KILL -f 'minikube tunnel' 2>/dev/null && echo -e "  ${YELLOW}→ SIGKILL minikube tunnel (còn sót sau 5s)${NC}" || true
else
  echo "  (không có minikube tunnel đang chạy)"
fi
# ssh-forward con (sudo ssh … .minikube/machines/… -L 443) thường là ROOT → cần sudo để nhả :443.
if pgrep -f '\.minikube/machines/.*-L ' >/dev/null 2>&1; then
  echo -e "  ${YELLOW}→ còn ssh-forward giữ cổng tunnel — cần sudo để dọn (có thể hỏi mật khẩu)${NC}"
  sudo pkill -f '\.minikube/machines/.*-L ' 2>/dev/null && echo "    đã kill ssh-forward" || echo -e "    ${YELLOW}(bỏ qua — không có quyền / không còn)${NC}"
fi
# Port-forward tạm (benchmark / deploy script có thể để sót, giữ cổng 1944x…).
if pgrep -f 'kubectl port-forward' >/dev/null 2>&1; then
  pkill -f 'kubectl port-forward' 2>/dev/null && echo "  → đã dừng kubectl port-forward còn sót"
else
  echo "  (không có kubectl port-forward nào)"
fi

# ── [2/4] Dọn đa-mạng cũ (nếu có) — để minikube stop/delete không lỗi (giống up.sh) ──
echo -e "${BLUE}[2/4] Dọn đa-mạng cũ (multi-home) nếu có${NC}"
docker network disconnect -f "$BANK" "$CUST" 2>/dev/null && echo "  (gỡ multi-home bank cũ)" || true
docker network disconnect -f "$TPP"  "$CUST" 2>/dev/null && echo "  (gỡ multi-home tpp cũ)"  || true

# ── [2b/4] Xóa dữ liệu TEST trong DB trước khi dừng (chỉ chế độ STOP; --delete đã wipe sạch) ─────
# Mục tiêu: KHÔNG để dữ liệu test (PSU identity + consent RAR) tích lũy qua các đợt. Phạm vi CHỈ
# customer_identity (auth-server) — service-data (mongo customer/account…) + Vault keys do up.sh
# re-import/re-setup nên KHÔNG đụng ở đây. (up.sh cũng tự xóa lúc start — đây là lớp an toàn thứ 2.)
if ! $DELETE; then
  echo -e "${BLUE}[2b/4] Xóa dữ liệu test trong DB (customer_identity) trước khi dừng${NC}"
  PG_NS=bank-cluster-nsp; PG_CON=postgresql; AUTH_DB=customer_identity
  if minikube status -p "$BANK" 2>/dev/null | grep -q "host: Running" \
     && kubectl exec -n "$PG_NS" --context "$BANK" deploy/postgres -c "$PG_CON" -- \
          psql -U user -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$AUTH_DB'" 2>/dev/null | grep -q 1 \
     && [ -n "$(kubectl exec -n "$PG_NS" --context "$BANK" deploy/postgres -c "$PG_CON" -- \
          psql -U user -d "$AUTH_DB" -tAc "SELECT to_regclass('public.customer')" 2>/dev/null | tr -d '[:space:]')" ]; then
    kubectl exec -n "$PG_NS" --context "$BANK" deploy/postgres -c "$PG_CON" -- \
      psql -U user -d "$AUTH_DB" -c \
      "TRUNCATE customer, customer_credential, consent_metadata, consent_resources RESTART IDENTITY CASCADE" >/dev/null 2>&1 \
      && echo -e "  ${GREEN}✓ đã xóa PSU identity + consent (customer_identity)${NC}" \
      || echo -e "  ${YELLOW}⚠ xóa lỗi (bỏ qua — DB ephemeral cũng mất khi stop)${NC}"
  else
    echo "  (bank cluster không chạy / DB chưa có — bỏ qua, không cần xóa)"
  fi
else
  echo -e "${BLUE}[2b/4] --delete: bỏ qua xóa DB (minikube delete wipe toàn bộ disk)${NC}"
fi

# ── [3/4] Dừng 3 cluster theo THỨ TỰ ĐẢO (customer → tpp → bank) ─────────────────────
if $DELETE; then
  echo -e "${RED}[3/4] DELETE 3 cluster (xóa hẳn — giải phóng disk, IP sẽ đổi lần sau)${NC}"
else
  echo -e "${BLUE}[3/4] STOP 3 cluster (giữ trạng thái stopped — up.sh khởi động lại nhanh)${NC}"
fi
for p in "$CUST" "$TPP" "$BANK"; do
  echo "  ⏹ minikube $ACTION -p $p"
  if minikube "$ACTION" -p "$p" >/dev/null 2>&1; then
    echo -e "    ${GREEN}ok${NC}"
  else
    echo -e "    ${YELLOW}⚠ $ACTION $p có cảnh báo (có thể đã dừng/không tồn tại)${NC}"
  fi
done

# ── [4/4] Tổng kết ──────────────────────────────────────────────────────────────────
echo -e "${BLUE}[4/4] Trạng thái sau khi dừng${NC}"
minikube profile list 2>/dev/null | grep -E "PROFILE|$BANK|$TPP|$CUST" || true
echo
if pgrep -f 'minikube tunnel' >/dev/null 2>&1 || pgrep -f '\.minikube/machines/.*-L ' >/dev/null 2>&1; then
  echo -e "${YELLOW}⚠ Vẫn còn tiến trình tunnel/ssh-forward — kiểm tra: pgrep -af 'minikube tunnel|machines.*-L '${NC}"
else
  echo -e "${GREEN}✓ Tunnel đã tắt (không còn tiến trình giữ cổng).${NC}"
fi
if $DELETE; then
  echo -e "${GREEN}✓ Đã XÓA 3 cluster. Khởi động lại: chạy lại pipeline tạo cluster rồi ./up.sh${NC}"
else
  echo -e "${GREEN}✓ Đã DỪNG 3 cluster (stopped). Khởi động lại: ./up.sh${NC}"
fi
