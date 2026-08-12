# TPP domain — `tpp.openbanking.dev` (KHÔNG port)

`tpp-service` truy cập từ host qua **`http://tpp.openbanking.dev`** (cổng 80, KHÔNG cần `:30081`).

Domain `tpp.openbanking.dev` dùng ở 2 ngữ cảnh:
1. **Host debug**: `curl http://tpp.openbanking.dev/tpp/token` (qua loopback-IP 127.0.0.3 + --ports).
2. **Cross-cluster** (`redirect_uri` + `AGENT_TPP_BASEURL`): customer-agent (pod) tới qua `hostAliases`
   → tpp-node-IP:30081 (NodePort). **Phần này GIỮ cổng 30081 nội-bộ** (không user-typed) để không
   phải đổi flow đã verify. Host thì port-less.

> ⚠ P1/P2 dùng HTTP. `redirect_uri = http://tpp.openbanking.dev:30081/tpp/callback` (nội-bộ
> cross-cluster). Hardening (P3) sẽ chuyển sang https + bỏ cổng.

## Cơ chế: loopback-IP riêng + `--ports`

Giống customer (xem `customer/docs/readme.md`). tpp bind **loopback-IP 127.0.0.3** để cổng 80 không
đụng bank(127.0.0.1)/customer(127.0.0.2):

```
host curl http://tpp.openbanking.dev   (/etc/hosts: 127.0.0.3)
   → 127.0.0.3:80 ──(docker port)──► tpp node ──► NodePort 30081 ──► pod :8080
```

## Các bước (theo thứ tự)

### 1. Cluster có port-mapping loopback (1 lần) — đã có trong `02-create-clusters.sh`
```bash
minikube start --profile tpp-cluster-profile ... --ports=127.0.0.3:80:30081
```
Recreate (tpp có Vault inmem → re-setup ĐẦY ĐỦ):
```bash
minikube delete --profile tpp-cluster-profile
minikube start  --profile tpp-cluster-profile --driver docker --memory 3072 --cpus 3 \
  --kubernetes-version v1.32.0 --disk-size 40g --container-runtime docker --ports=127.0.0.3:80:30081
# kiểm: docker port tpp-cluster-profile | grep 80  → 30081/tcp -> 127.0.0.3:80
./tpp/scripts/01-deploy-vault.sh
./tpp/scripts/02-vault-configure.sh
./tpp/scripts/03-publish-ca-to-bank.sh
./tpp/scripts/04-deploy-tpp-service.sh
./customer/02-deploy-customer-agent.sh   # tpp-node-IP đổi → cập nhật hostAlias
```

### 2. Service NodePort 30081 — đã set trong `tpp/kubernetes/tpp-service.yaml`.

### 3. redirect_uri (nội-bộ, GIỮ :30081) khớp 3 nơi = `http://tpp.openbanking.dev:30081/tpp/callback`
- auth-server `AuthorizationServerConfig.java` (RegisteredClient `tpp-fintech-app`).
- tpp `application.yml` → `tpp.client.redirect-uri`.
- customer-agent env `AGENT_TPP_BASEURL=http://tpp.openbanking.dev:30081` (cross-cluster node-IP).

### 4. /etc/hosts (sudo, 1 lần) — xem `customer/docs/readme.md` (gộp 3 dòng 127.0.0.1/2/3).

### 5. Test host (KHÔNG port)
```bash
curl -s http://tpp.openbanking.dev/tpp/token                                   # JWT (client_credentials)
curl -s -X POST "http://tpp.openbanking.dev/tpp/authcode/initiate?customerId=5dbd11af-9e2e-44d0-889d-65db85b55ce6"  # PAR → request_uri
```
> Tạm thời (chưa /etc/hosts): `curl --resolve tpp.openbanking.dev:80:127.0.0.3 http://tpp.openbanking.dev/...`

## Sự cố
- Token `500` + Vault `kubernetes/login 403`: Vault inmem mất config → `02-vault-configure.sh` +
  `03-publish-ca-to-bank.sh` + `kubectl rollout restart deploy/tpp-service -n tpp-cluster-nsp --context tpp-cluster-profile`.
- `000`: thiếu `--ports` (`docker port tpp-cluster-profile | grep 80`) → recreate (bước 1).
