#!/bin/bash
# ============================================================
# shutdown.sh - Stops the WHOLE system safely (3 clusters + tunnel) with ONE command.
#               It is the INVERSE of up.sh.
#
#   ./shutdown.sh            # STOP (default, LIGHT): keeps the clusters in the stopped state.
#                            #   Pairs with `./up.sh` (reconcile) - fast restart,
#                            #   the disks are kept. Note: the in-memory Vault loses its configuration and mongo its data on
#                            #   stop (up.sh sets them up and imports the data again).
#   ./shutdown.sh --delete   # DELETE (HEAVY): `minikube delete` of the 3 clusters, frees the disk.
#                            #   Note: the cluster creation pipeline must be run again next time (02-create-clusters...)
#                            #   and the cluster IPs change -> update the hostAlias (02-deploy-customer-agent.sh).
#
# STOP ORDER = INVERSE of the up.sh start order (bank->tpp->customer):
#   tunnel/port-forward -> customer -> tpp -> bank
#   (customer depends on tpp/bank, so customer is stopped FIRST.)
#
# The loopbacks 127.0.0.2:80 (customer) / 127.0.0.3:80 (tpp) are docker port mappings INSIDE the minikube
# container -> they DISAPPEAR when the cluster stops; no manual clean-up is needed.
#
# Tunnel: `minikube tunnel` (user) spawns a child process `sudo ssh ... -L 443/80/...` (root) that holds
# 127.0.0.1:443. SIGTERM to the parent lets minikube clean up its ssh child; leftovers are removed with sudo pkill (asks for the password).
# ============================================================
set -uo pipefail
GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
BANK=bank-cluster-profile; TPP=tpp-cluster-profile; CUST=customer-cluster-profile
DELETE=false
[ "${1:-}" = "--delete" ] && DELETE=true
ACTION=stop; $DELETE && ACTION=delete

# -- [1/4] Stop the tunnel + leftover ssh-forward + port-forward -------------------------
echo -e "${BLUE}[1/4] Stopping tunnel / port-forward${NC}"
if pgrep -f 'minikube tunnel' >/dev/null 2>&1; then
  pkill -TERM -f 'minikube tunnel' 2>/dev/null && echo "  -> SIGTERM minikube tunnel (lets it clean up its routes + ssh child)"
  for _ in 1 2 3 4 5; do pgrep -f 'minikube tunnel' >/dev/null 2>&1 || break; sleep 1; done
  pkill -KILL -f 'minikube tunnel' 2>/dev/null && echo -e "  ${YELLOW}-> SIGKILL minikube tunnel (still running after 5s)${NC}" || true
else
  echo "  (no minikube tunnel running)"
fi
# The ssh-forward child (sudo ssh ... .minikube/machines/... -L 443) usually runs as ROOT -> sudo is needed to release :443.
if pgrep -f '\.minikube/machines/.*-L ' >/dev/null 2>&1; then
  echo -e "  ${YELLOW}-> an ssh-forward still holds the tunnel port - sudo is needed to remove it (may ask for the password)${NC}"
  sudo pkill -f '\.minikube/machines/.*-L ' 2>/dev/null && echo "    ssh-forward killed" || echo -e "    ${YELLOW}(skipped - no permission / already gone)${NC}"
fi
# Temporary port-forwards (benchmark / deployment scripts may leave them behind, holding ports 1944x...).
if pgrep -f 'kubectl port-forward' >/dev/null 2>&1; then
  pkill -f 'kubectl port-forward' 2>/dev/null && echo "  -> leftover kubectl port-forward stopped"
else
  echo "  (no kubectl port-forward)"
fi

# -- [2/4] Remove an old multi-homing (if any) - so that minikube stop/delete do not fail (as in up.sh) --
echo -e "${BLUE}[2/4] Removing an old multi-homing, if any${NC}"
docker network disconnect -f "$BANK" "$CUST" 2>/dev/null && echo "  (old bank multi-homing removed)" || true
docker network disconnect -f "$TPP"  "$CUST" 2>/dev/null && echo "  (old tpp multi-homing removed)"  || true

# -- [2b/4] Remove the TEST data from the database before stopping (STOP mode only; --delete wipes everything) -----
# Goal: test data (PSU identities + RAR consents) must NOT accumulate across campaigns. Scope: ONLY
# customer_identity (auth-server) - service data (mongo customer/account...) + Vault keys are imported/set up again
# by up.sh and are NOT touched here. (up.sh also clears it at start - this is a second safety layer.)
if ! $DELETE; then
  echo -e "${BLUE}[2b/4] Removing the test data from the database (customer_identity) before stopping${NC}"
  PG_NS=bank-cluster-nsp; PG_CON=postgresql; AUTH_DB=customer_identity
  if minikube status -p "$BANK" 2>/dev/null | grep -q "host: Running" \
     && kubectl exec -n "$PG_NS" --context "$BANK" deploy/postgres -c "$PG_CON" -- \
          psql -U user -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$AUTH_DB'" 2>/dev/null | grep -q 1 \
     && [ -n "$(kubectl exec -n "$PG_NS" --context "$BANK" deploy/postgres -c "$PG_CON" -- \
          psql -U user -d "$AUTH_DB" -tAc "SELECT to_regclass('public.customer')" 2>/dev/null | tr -d '[:space:]')" ]; then
    kubectl exec -n "$PG_NS" --context "$BANK" deploy/postgres -c "$PG_CON" -- \
      psql -U user -d "$AUTH_DB" -c \
      "TRUNCATE customer, customer_credential, consent_metadata, consent_resources RESTART IDENTITY CASCADE" >/dev/null 2>&1 \
      && echo -e "  ${GREEN}[ok] PSU identities + consents removed (customer_identity)${NC}" \
      || echo -e "  ${YELLOW}[warn] removal failed (skipped - the ephemeral database is lost on stop anyway)${NC}"
  else
    echo "  (bank cluster not running / database not present - skipped, nothing to remove)"
  fi
else
  echo -e "${BLUE}[2b/4] --delete: database clean-up skipped (minikube delete wipes the whole disk)${NC}"
fi

# -- [3/4] Stop the 3 clusters in INVERSE ORDER (customer -> tpp -> bank) ---------------
if $DELETE; then
  echo -e "${RED}[3/4] DELETE the 3 clusters (removed completely - disk freed, the IPs change next time)${NC}"
else
  echo -e "${BLUE}[3/4] STOP the 3 clusters (kept in the stopped state - up.sh restarts them quickly)${NC}"
fi
for p in "$CUST" "$TPP" "$BANK"; do
  echo "  - minikube $ACTION -p $p"
  if minikube "$ACTION" -p "$p" >/dev/null 2>&1; then
    echo -e "    ${GREEN}ok${NC}"
  else
    echo -e "    ${YELLOW}[warn] $ACTION $p reported a warning (possibly already stopped / not existing)${NC}"
  fi
done

# -- [4/4] Summary ---------------------------------------------------------------------
echo -e "${BLUE}[4/4] State after the stop${NC}"
minikube profile list 2>/dev/null | grep -E "PROFILE|$BANK|$TPP|$CUST" || true
echo
if pgrep -f 'minikube tunnel' >/dev/null 2>&1 || pgrep -f '\.minikube/machines/.*-L ' >/dev/null 2>&1; then
  echo -e "${YELLOW}[warn] tunnel/ssh-forward processes are still running - check with: pgrep -af 'minikube tunnel|machines.*-L '${NC}"
else
  echo -e "${GREEN}[ok] Tunnel stopped (no process holds the ports).${NC}"
fi
if $DELETE; then
  echo -e "${GREEN}[ok] The 3 clusters were DELETED. To restart: run the cluster creation pipeline again, then ./up.sh${NC}"
else
  echo -e "${GREEN}[ok] The 3 clusters were STOPPED. To restart: ./up.sh${NC}"
fi
