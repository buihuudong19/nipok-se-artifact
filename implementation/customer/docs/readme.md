# Customer domain — `customer.openbanking.dev` (KHÔNG port)

`customer-agent` (PSU headless) truy cập từ host qua **`http://customer.openbanking.dev`** (cổng 80,
KHÔNG cần `:30090`) — đồng nhất `bank.openbanking.dev`.

## Cơ chế: loopback-IP riêng + `--ports`

WSL2 + minikube `docker` driver: host KHÔNG route tới IP node minikube → vào service qua
**docker port-mapping** (`minikube start --ports`). Muốn 3 domain cùng dùng cổng 80 mà KHÔNG đụng
nhau → mỗi cluster bind một **loopback-IP riêng** (Linux 127.0.0.0/8 đều là loopback):

| Domain | /etc/hosts | --ports | docker mapping |
|---|---|---|---|
| bank.openbanking.dev | 127.0.0.1 | (tunnel/30443) | — |
| **customer.openbanking.dev** | **127.0.0.2** | `127.0.0.2:80:30090` | `30090→127.0.0.2:80` |
| **tpp.openbanking.dev** | **127.0.0.3** | `127.0.0.3:80:30081` | `30081→127.0.0.3:80` |

```
host curl http://customer.openbanking.dev        (/etc/hosts: 127.0.0.2)
   → 127.0.0.2:80 ──(docker port)──► customer node ──► NodePort 30090 ──► pod :8080
```

> 2 phạm vi DNS độc lập: **host** `/etc/hosts` (→127.0.0.x, qua --ports) vs **trong pod**
> `hostAliases` (bank/tpp → node-IP, cross-cluster). Không xung đột.

## Các bước (theo thứ tự)

### 1. Cluster có port-mapping loopback (1 lần) — đã có trong `02-create-clusters.sh`
```bash
minikube start --profile customer-cluster-profile ... --ports=127.0.0.2:80:30090
```
Cluster tạo TRƯỚC dòng này → recreate (rẻ, chỉ agent):
```bash
minikube delete --profile customer-cluster-profile
minikube start  --profile customer-cluster-profile --driver docker --memory 2048 --cpus 3 \
  --kubernetes-version v1.32.0 --disk-size 30g --container-runtime docker --ports=127.0.0.2:80:30090
# kiểm: docker port customer-cluster-profile | grep 80  → 30090/tcp -> 127.0.0.2:80
```

### 2. Service NodePort 30090 — đã set trong `customer/kubernetes/customer-agent.yaml`.

### 3. /etc/hosts (sudo, 1 lần)
```bash
sudo tee -a /etc/hosts <<'EOF'
127.0.0.1  bank.openbanking.dev
127.0.0.2  customer.openbanking.dev
127.0.0.3  tpp.openbanking.dev
EOF
```

### 4. Deploy agent (tự docker network connect + điền hostAlias bank/tpp)
```bash
./customer/02-deploy-customer-agent.sh
```

### 5. Test (KHÔNG port)
```bash
curl -s http://customer.openbanking.dev/agent/health        # OK
curl -s -X POST "http://customer.openbanking.dev/agent/run?customerId=5dbd11af-9e2e-44d0-889d-65db85b55ce6" \
  | python3 -m json.tool                                     # httpStatus 200 + data
```
> Chưa thêm /etc/hosts? Test tạm: `curl --resolve customer.openbanking.dev:80:127.0.0.2 http://customer.openbanking.dev/...`

## ⚠ Khởi động lại cluster / sau reboot → CHỈ 1 LỆNH

```bash
./up.sh
```
`up.sh` (ở repo root) tự làm hết (đã test): `minikube start` 3 cluster (+update-context) → **tự phát
hiện Vault inmem mất config → re-setup** → restart agent. Xong là test được luôn.

**Cross-cluster KHÔNG cần `docker network connect`:** pod customer reach bank/tpp qua **host-routing**
giữa các docker bridge (host forward — như tpp→bank vốn chạy). Trước đây script dùng
`docker network connect` (đa-mạng) → node customer có 3 IP → `minikube start/status/ip` LỖI
`container addresses should have 2 values, got 4 values`. **Đã bỏ multi-home** → mọi lệnh minikube
chạy bình thường. (`up.sh`/[0]deploy còn `docker network disconnect` phòng vệ để dọn multi-home cũ.)
Lý do vẫn cần `up.sh` (không chỉ 3 lệnh start): Vault inmem mất config phải re-setup **SAU** start.

> Nếu RECREATE cluster (không phải restart) → IP đổi → chạy `./customer/02-deploy-customer-agent.sh`
> (cập nhật hostAlias) thay vì chỉ `up.sh`.
>
> Hướng triệt để footgun (để dành, tốn vì phải recreate bank): cả 3 cluster cùng 1 docker network
> `minikube start --network openbanking-shared` → khỏi `docker network connect` → 3 lệnh start chạy
> thẳng. Nhưng vẫn còn bước Vault (nên dùng `up.sh` vẫn gọn hơn).

### Thủ công từng bước (nếu cần debug, tương đương up.sh)
```bash
./customer/net-disconnect.sh                                   # tháo đa-mạng
minikube start -p bank-cluster-profile && minikube start -p tpp-cluster-profile && minikube start -p customer-cluster-profile
./tpp/scripts/02-vault-configure.sh && ./tpp/scripts/03-publish-ca-to-bank.sh \
  && kubectl rollout restart deploy/tpp-service -n tpp-cluster-nsp --context tpp-cluster-profile   # nếu Vault mất config
./customer/02-deploy-customer-agent.sh                          # nối lại + (re)deploy agent
```

## Sự cố
- `000/refused`: thiếu `--ports` (`docker port customer-cluster-profile | grep 80`) → recreate (bước 1).
- Journey `ConnectException` bank/tpp: node chưa nối bridge → chạy lại `02-deploy-customer-agent.sh` (đã tự `docker network connect`).
- `minikube start` lỗi "container addresses should have 2 values": node customer đa-mạng → `./customer/net-disconnect.sh` rồi start lại.
- kubectl `connection refused 127.0.0.1:<port>`: cổng API đổi sau restart → `minikube update-context -p customer-cluster-profile`.
