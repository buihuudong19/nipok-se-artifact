#!/bin/bash
# G6 — kiểm tra tính toàn vẹn hash-chain của SECURITY_AUDIT (phát hiện xoá/sửa bản ghi).
#   ./verify-audit-chain.sh
set -uo pipefail
CTX="${BANK_CONTEXT:-bank-cluster-profile}"
kubectl logs -n bank-cluster-nsp deploy/auth-server -c auth-server --context "$CTX" 2>&1 \
  | grep "SECURITY_AUDIT" | grep -oE '\{.*\}' > /tmp/audit.jsonl
echo "events: $(wc -l < /tmp/audit.jsonl)"
python3 - <<'PY'
import json, hashlib, base64
sha=lambda s: base64.urlsafe_b64encode(hashlib.sha256(s.encode()).digest()).decode().rstrip('=')
canon=lambda ev: json.dumps({k:v for k,v in ev.items() if k!='hash'}, sort_keys=True, separators=(',',':'), ensure_ascii=False)
events=sorted([json.loads(l) for l in open('/tmp/audit.jsonl') if l.strip()], key=lambda e:e['seq'])
prev='GENESIS'
for e in events:
    if e['prevHash']!=prev or sha(prev+canon(e))!=e['hash']:
        print(f'✗ CHAIN GÃY tại seq={e["seq"]} → audit BỊ XOÁ/SỬA'); raise SystemExit(1)
    prev=e['hash']
print(f'✓ CHAIN HỢP LỆ ({len(events)} event) — không bị tamper')
PY
