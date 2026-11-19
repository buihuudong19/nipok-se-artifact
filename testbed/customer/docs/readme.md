# Customer domain - `customer.openbanking.dev` (no port)

The `customer-agent` (headless PSU) is reached from the host at `http://customer.openbanking.dev` (port 80,
no `:30090` needed), in the same way as `bank.openbanking.dev`.

## Mechanism: one loopback IP per cluster + `--ports`

With WSL2 and the minikube `docker` driver, the host does NOT route to the minikube node IP, so services are reached
through docker port mapping (`minikube start --ports`). To let the three domains use port 80 without conflicts,
each cluster binds its own loopback IP (every Linux address in 127.0.0.0/8 is loopback):

| Domain | /etc/hosts | --ports | docker mapping |
|---|---|---|---|
| bank.openbanking.dev | 127.0.0.1 | (tunnel/30443) | - |
| customer.openbanking.dev | 127.0.0.2 | `127.0.0.2:80:30090` | `30090->127.0.0.2:80` |
| tpp.openbanking.dev | 127.0.0.3 | `127.0.0.3:80:30081` | `30081->127.0.0.3:80` |

```
host curl http://customer.openbanking.dev        (/etc/hosts: 127.0.0.2)
   -> 127.0.0.2:80 --(docker port)--> customer node --> NodePort 30090 --> pod :8080
```

> Two independent DNS scopes: the host `/etc/hosts` (-> 127.0.0.x, through --ports) and, inside the pod,
> `hostAliases` (bank/tpp -> node IP, cross-cluster). They do not conflict.

## Steps (in order)

### 1. Cluster with loopback port mapping (once) - already in `02-create-clusters.sh`
```bash
minikube start --profile customer-cluster-profile ... --ports=127.0.0.2:80:30090
```
A cluster created BEFORE this option must be recreated (cheap, only the agent):
```bash
minikube delete --profile customer-cluster-profile
minikube start  --profile customer-cluster-profile --driver docker --memory 2048 --cpus 3 \
  --kubernetes-version v1.32.0 --disk-size 30g --container-runtime docker --ports=127.0.0.2:80:30090
# check: docker port customer-cluster-profile | grep 80  -> 30090/tcp -> 127.0.0.2:80
```

### 2. NodePort service 30090 - set in `customer/kubernetes/customer-agent.yaml`.

### 3. /etc/hosts (sudo, once)
```bash
sudo tee -a /etc/hosts <<'EOF'
127.0.0.1  bank.openbanking.dev
127.0.0.2  customer.openbanking.dev
127.0.0.3  tpp.openbanking.dev
EOF
```

### 4. Deploy the agent (fills the bank/tpp hostAliases)
```bash
./customer/02-deploy-customer-agent.sh
```

### 5. Test (no port)
```bash
curl -s http://customer.openbanking.dev/agent/health        # OK
curl -s -X POST "http://customer.openbanking.dev/agent/run?customerId=5dbd11af-9e2e-44d0-889d-65db85b55ce6" \
  | python3 -m json.tool                                     # httpStatus 200 + data
```
> Without the /etc/hosts entries: `curl --resolve customer.openbanking.dev:80:127.0.0.2 http://customer.openbanking.dev/...`

## Restarting the clusters / after a reboot: one command

```bash
./up.sh
```
`up.sh` (at the testbed root) does everything: `minikube start` of the 3 clusters (+ update-context), detection of an
in-memory Vault that lost its configuration and new set-up, restart of the agent. Tests can run right afterwards.

Cross-cluster traffic needs NO `docker network connect`: the customer pod reaches bank/tpp through host routing
between the docker bridges (the host forwards, as for tpp->bank). Earlier versions used `docker network connect`
(multi-homing): the customer node then had 3 IPs and `minikube start/status/ip` FAILED with
`container addresses should have 2 values, got 4 values`. Multi-homing has been removed, so every minikube command
works normally (`up.sh` and step [0] of the deployment still run `docker network disconnect` to clean up an old
multi-homing). `up.sh` is still needed (not only 3 start commands) because the in-memory Vault must be set up again
AFTER the start.

> After RECREATING a cluster (not a restart) the IPs change: run `./customer/02-deploy-customer-agent.sh`
> (updates the hostAliases) instead of only `up.sh`.
>
> A more radical option (not used, because the bank cluster would have to be recreated): all 3 clusters on one docker
> network `minikube start --network openbanking-shared`, so that 3 start commands suffice. The Vault step would remain,
> so `up.sh` is still simpler.

### Manual steps (for debugging, equivalent to up.sh)
```bash
./customer/net-disconnect.sh                                   # removes an old multi-homing
minikube start -p bank-cluster-profile && minikube start -p tpp-cluster-profile && minikube start -p customer-cluster-profile
./tpp/scripts/02-vault-configure.sh && ./tpp/scripts/03-publish-ca-to-bank.sh \
  && kubectl rollout restart deploy/tpp-service -n tpp-cluster-nsp --context tpp-cluster-profile   # if Vault lost its configuration
./customer/02-deploy-customer-agent.sh                          # (re)deploys the agent
```

## Troubleshooting
- `000/refused`: `--ports` missing (`docker port customer-cluster-profile | grep 80`) -> recreate (step 1).
- Journey `ConnectException` to bank/tpp: the hostAliases are outdated (cluster recreated) -> run `02-deploy-customer-agent.sh` again.
- `minikube start` fails with "container addresses should have 2 values": the customer node is multi-homed -> `./customer/net-disconnect.sh`, then start again.
- kubectl `connection refused 127.0.0.1:<port>`: the API port changed after a restart -> `minikube update-context -p customer-cluster-profile`.
