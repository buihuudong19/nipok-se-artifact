# TPP domain - `tpp.openbanking.dev`

`tpp-service` (the third-party provider) runs in the cluster `tpp-cluster-profile`, namespace `tpp-cluster-nsp`.
It serves HTTPS with mutual TLS on container port 8080 (`server.ssl`, `client-auth: want`) and is exposed as
NodePort 30081. On `/tpp/*`, `TppMtlsFilter` checks the client certificate `CN=customer-agent` according to
`TPP_G4_MTLS_MODE` (`off` | `log` | `enforce`, default `log`). `TPP_TLS_ENABLED=false` switches back to plain HTTP.

The name `tpp.openbanking.dev` is used in two contexts:

1. Cross-cluster (`redirect_uri` and `AGENT_TPP_BASEURL`): the customer-agent pod reaches the TPP through
   `hostAliases` -> TPP node IP, port 30081 (NodePort).
2. Host access (debugging, and the customer-data import done by `up.sh`): through the loopback IP 127.0.0.3 and
   the docker port mapping `127.0.0.3:80 -> 30081`. The listener behind this mapping is TLS, so the host URL is
   `https://tpp.openbanking.dev:80/...`.

## Mechanism: own loopback IP + `--ports`

As for the customer domain (see `customer/docs/readme.md`), the TPP cluster binds its own loopback IP
127.0.0.3, so that port 80 does not collide with the bank (127.0.0.1) or the customer domain (127.0.0.2):

```
host curl https://tpp.openbanking.dev:80     (/etc/hosts: 127.0.0.3)
   -> 127.0.0.3:80 --(docker port)--> tpp node --> NodePort 30081 --> pod :8080 (TLS)
```

## Steps (in order)

### 1. Cluster with loopback port mapping (once) - already in `02-create-clusters.sh`
```bash
minikube start --profile tpp-cluster-profile ... --ports=127.0.0.3:80:30081
```
Re-creating the cluster (Vault keeps its data in memory, so the full set-up is needed again):
```bash
minikube delete --profile tpp-cluster-profile
minikube start  --profile tpp-cluster-profile --driver docker --memory 3072 --cpus 3 \
  --kubernetes-version v1.32.0 --disk-size 40g --container-runtime docker --ports=127.0.0.3:80:30081
# check: docker port tpp-cluster-profile | grep 80  -> 30081/tcp -> 127.0.0.3:80
./tpp/scripts/01-deploy-vault.sh
./tpp/scripts/02-vault-configure.sh
./tpp/scripts/03-publish-ca-to-bank.sh
./tpp/scripts/04-deploy-tpp-service.sh
./customer/02-deploy-customer-agent.sh   # the TPP node IP changed -> update the hostAlias of the agent
```
The secrets of a re-created cluster are also gone: `up.sh` reissues the TLS material (`tpp-tls`, through
`bank/kubernetes/setup-g4-certs.sh`) when the secret is missing, and the JARM keys are generated again with
`bank/kubernetes/generate-jarm-keys.sh` (see `bank/spring-cloud/authorization-server/docs/jarm.md`).

### 2. NodePort service 30081 - defined in `tpp/kubernetes/tpp-service.yaml`.

### 3. The redirect_uri `https://tpp.openbanking.dev:30081/tpp/callback` must match in three places
- auth-server `AuthorizationServerConfig.java` (RegisteredClient `tpp-fintech-app`);
- tpp `application.yml` -> `tpp.client.redirect-uri`;
- customer-agent env `AGENT_TPP_BASEURL=https://tpp.openbanking.dev:30081` (`customer/kubernetes/customer-agent.yaml`).

### 4. /etc/hosts (sudo, once) - see `customer/docs/readme.md` (one block for 127.0.0.1/2/3).

### 5. Host test
```bash
curl -sk https://tpp.openbanking.dev:80/tpp/token                       # JWT (client_credentials)
curl -sk -X POST "https://tpp.openbanking.dev:80/tpp/authcode/initiate?customerId=5dbd11af-9e2e-44d0-889d-65db85b55ce6"  # PAR -> request_uri
```
`-k` is used because the host does not hold the CA of the TPP server certificate. With `TPP_G4_MTLS_MODE=enforce`
the request must also present the agent workload certificate, as `up.sh` does for the data import.
Without the /etc/hosts entries: `curl -sk --resolve tpp.openbanking.dev:80:127.0.0.3 https://tpp.openbanking.dev:80/...`

## Troubleshooting
- Token `500` and Vault `kubernetes/login 403`: the in-memory Vault lost its configuration -> `02-vault-configure.sh`,
  `03-publish-ca-to-bank.sh`, then
  `kubectl rollout restart deploy/tpp-service -n tpp-cluster-nsp --context tpp-cluster-profile` (`up.sh` does this
  automatically).
- `000`: `--ports` is missing (`docker port tpp-cluster-profile | grep 80`) -> re-create the cluster (step 1).
