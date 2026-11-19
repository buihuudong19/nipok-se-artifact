#!/bin/bash
# Checks the integrity of the SECURITY_AUDIT hash chain (detects deleted/modified records).
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
        print(f'[fail] CHAIN BROKEN at seq={e["seq"]} -> audit records DELETED/MODIFIED'); raise SystemExit(1)
    prev=e['hash']
print(f'[ok] CHAIN VALID ({len(events)} events) - not tampered with')
PY
