#!/usr/bin/env bash
# ============================================================================
# run-R1C7.sh - control point of the measurements of the security-cost ablation and operational tests (Reviewer 1, Comment 7).
#
# The data are written to $C7_DATA (default testbed/bank/benchmark-R1-C7), separate from benchmark-R1-C6:
#   jmh/ablation   JMH cost breakdown: NipokAblationBenchmark (agent side, auth-server side), EnvelopeAblationBenchmark
#   jmh/params     saved JMH jar (crypto-jmh-c7-1.0.0-jmh.jar + jmh-jar.md5), build.txt (JDK, library versions)
#   e2e/hops       time of every stage at the ingress gateway, seven mechanisms, fixed 8 journeys/s (Envoy access log),
#                  TLS connections per journey (access log), access-token signing time (auth_server_ed25519_sign_seconds);
#                  hops.txt. The Istio of the testbed (demo profile) records only the default Envoy stats group, without the
#                  TLS listener counters listener.*.ssl.*, so an empty envoy-ssl-*.txt is expected (gateway configuration unchanged).
#                  The gateway of the testbed writes no access log, so the hops step applies the Telemetry resource
#                  $GW_TEL (istio-ingressgateway only, provider envoy), checks it with a marked request and removes it at the end of
#                  the step (also on error or Ctrl-C); e2e/hops/gateway-accesslog.txt records the configuration before and after.
#   e2e/burst      burst 8 -> 64 -> 8 journeys/s (60 + 30 + 90 s), seven mechanisms, 3 runs; burst.txt.
#                  The transaction container of the bank was OOM-killed at its 400Mi limit in a first burst run, after which every
#                  journey timed out; the step therefore raises limits.memory of transaction (C7_TX_MEM_LIMIT, default 1Gi),
#                  keeps requests.memory and the heap sizing of the JVM (JAVA_TOOL_OPTIONS=-XX:MaxRAM=<previous limit>) and restores
#                  the resources at the end of the step, on error and on Ctrl-C; c7_burst.py
#                  marks invalid runs (restarted container, no successful journey, failed data step)
#   e2e/probe      key registration (seven methods), NIPoK failure classes, lockout, key lifecycle (revocation, rotation,
#                  recovery by operator actions), concurrent authentication (C7Probe.java); probe.json, probe-reasons.txt;
#                  e2e/probe/restart: auth-server restart (pod deleted) with the in-memory nonce store (C7Probe, restart phase)
#   e2e/tls        Envoy CPU per TLS handshake (bench-handshake-load.sh of the testbed)
#   logs/          console log of every step;   MANIFEST.txt  trace of every step (file md5, environment)
# The e2e steps run the run-all-psu.sh of Comment 6 unchanged. run-all-psu.sh does `cd "$(dirname "$0")"` and takes
#   DIR=$(pwd) for bench-psu-auth.js and plot_loadtest.py, so C7 calls it through the link k6-psu-c7/run-all-psu.sh ->
#   ../k6-psu-auth/run-all-psu.sh (the same file; the link is created on first use): DIR = k6-psu-c7 and k6 runs the C7
#   scenarios (those of C6 + the burst scenario).
#   The load configuration (LT_COMMON, RL_UP) is read from run-R1C6.sh, so it is identical to C6.
# Rate limiter of the auth-server (as in C6): every e2e step (hops, burst, probe, tls) runs with
#   APP_RATELIMIT_PSU_PER_SEC and APP_RATELIMIT_PAR_PER_SEC equal to RL_PSU, RL_PAR of RL_UP in run-R1C6.sh (100000 req/s
#   per IP). At the start of every step (probe: right after the NIPoK setup) the script reads the values of the auth-server
#   deployment, resets them when they differ (kubectl set env, rollout, verify-as) and writes e2e/<step>/rate-limiter.txt.
# Images: hops, burst, probe and tls run only when the auth-server and customer-agent pods run the images measured in C6
#   (C6_IMG_AS, C6_IMG_AGENT below; `check` and MANIFEST print the imageID); on another host set C7_ALLOW_IMAGE_CHANGE=1.
#
# Usage (from testbed/bank, on the measurement host; NOT while a load test of C6 runs):
#   ./run-R1C7.sh check     # files, Gradle wrapper, JVM, auth-server bootJar, jar, clusters, tools
#   ./run-R1C7.sh build     # build the JMH jar of crypto-jmh-c7 (Nimbus/Tink/Conscrypt in the versions of the auth-server bootJar)
#   ./run-R1C7.sh smoke     # compile C7Probe, try the burst scenario with k6 (without the agent), check the syntax of
#                           #   c7_hops/c7_burst; then one short run of every benchmark (correctness gate); ~5 min
#   ./run-R1C7.sh hops      # ~1 h, clusters running   | ./run-R1C7.sh burst  # ~2 h, clusters running
#   ./run-R1C7.sh probe     # ~25 min, clusters running (deletes the auth-server pod 3 times at the end) | ./run-R1C7.sh tls  # ~2 min
#   ./run-R1C7.sh jmh       # ~70 min: stops the three clusters, Temurin 24+36, taskset 0-7, 5 forks x (8 + 10) x 1 s, -prof gc
#   ./run-R1C7.sh report    # recompute hops.txt, burst.txt from the existing data (read only)
#   ./run-R1C7.sh status    # show what exists
#   ./run-R1C7.sh diag      # read only: access-log configuration of the gateway, access-token signing provider of the auth-server
#   ./run-R1C7.sh postmortem   # read only: pods, logs and events of transaction and customer-aggregator; Prometheus (memory of
#                              #   transaction, request outcomes) per burst run; run it BEFORE restarting the testbed
#   ./run-R1C7.sh tx-mem-restore   # restore the original resources of transaction (when the burst step was killed)
#   ./run-R1C7.sh jmh-sunec # ~5 min, stops the three clusters: as_token_sign, as_token_encode with tokenProvider=SunEC
#   ./run-R1C7.sh export    # copy $C7_DATA to $EXPORT_DIR
#   Measure a step again: FORCE=1 ./run-R1C7.sh <step> (the old copy is renamed *.bak-<time>, also in EXPORT_DIR).
# ============================================================================
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"   # testbed root (holds bank/, customer/, tpp/, up.sh)
BANK="$REPO/bank"
C7_DIR="${C7_DIR:-$BANK/benchmark/crypto-jmh-c7}"
C7_DATA="${C7_DATA:-$BANK/benchmark-R1-C7}"
EXPORT_DIR="${EXPORT_DIR:-}"                                     # target of the export command (no default)
AS_LIBS="${AS_LIBS:-$BANK/spring-cloud/authorization-server/build/libs}"
LT_DIR="$BANK/kubernetes/loadtest/k6-psu-auth"                 # run-all-psu.sh of Comment 6 (called, never changed)
C7_LT="$BANK/kubernetes/loadtest/k6-psu-c7"                    # working directory of the e2e part of C7
E2E_DIR="$BANK/kubernetes/psu-mtls"                            # run-full-e2e-*.sh (setup of every mechanism)
SCRIPTS="$BANK/kubernetes/scripts"
ISTIO="${ISTIO:-$LT_DIR/istio_hops.py}"                        # istio_hops.py (Istio metrics per run; empty = skipped)
TEMURIN_JRE="${TEMURIN_JRE:-$HOME/jdks/temurin-24_36-jre}"   # same JRE as the JMH of Comment 6 (./run-R1C6.sh setup-jvm)
J_FORKS="${J_FORKS:-5}"; J_WI="${J_WI:-8}"; J_IT="${J_IT:-10}"; J_CPUS="${J_CPUS:-0-7}"; J_ISOLATE="${J_ISOLATE:-1}"
JVM_FLAGS="--enable-native-access=ALL-UNNAMED"              # Conscrypt loads a native library (as the ENTRYPOINT of the auth-server)
M7="${M7:-nipok,schnorr_interactive,ed25519,password,private_key_jwt,ml_dsa,mtls}"   # order of the WAN phase (mtls last)
C7_REPEATS="${C7_REPEATS:-3}"
BANK_URL="${BANK_URL:-https://bank.openbanking.dev:30443}"     # as in run-full-e2e-*.sh
PF_PORT="${C7_PF_PORT:-18091}"                                 # port-forward to /actuator/prometheus of the auth-server
KB="kubectl --context bank-cluster-profile"; BNS=bank-cluster-nsp; GWN=istio-system; GWD=istio-ingressgateway
CUST_NODE=customer-cluster-profile; NODE_MEM_MIN_MIB=4096
# images measured in C6 (image IDs recorded after the WAN phase of the statistical evaluation)
C6_IMG_AS="sha256:249ef148200ef86d4abc7822c1e3e37244e829a8aab92c323b5b33dd00ba2c14"
C6_IMG_AGENT="sha256:74c321856c05f2753f09165c35cabb5cf24bb0ea4229d84d673d59c04fb70b0e"
AS_LABEL="app.kubernetes.io/name=auth-server"
# run-all-psu.sh of C6 is called through the link in k6-psu-c7 (see the top of the file)
C7_RUNNER="$C7_LT/run-all-psu.sh"; RUNNER_LINK="../k6-psu-auth/run-all-psu.sh"
# temporary access log of the gateway in the hops step: 1 = on, 0 = off
GW_TEL="c7-gateway-access-log"; GW_ACCESSLOG="${C7_GW_ACCESSLOG:-1}"; GW_TEL_ON=0; GW_AL_STATE=""; GW_AL_OUT=""
# transaction in the burst step: new memory limit (0 = unchanged), keep the heap sizing (1) or not (0)
TX_DEP=transaction; TX_C=transaction; TX_MEM="${C7_TX_MEM_LIMIT:-1Gi}"; TX_PIN="${C7_TX_PIN_HEAP:-1}"; TX_ON=0; TX_ORIG=""; TX_OUT=""

say(){ printf '\n== %s\n' "$*"; }
ok(){  printf '   [ok] %s\n' "$*"; }
warn(){ printf '   [warn] %s\n' "$*"; }
die(){ printf '\nERROR: %s\n' "$*" >&2; exit 1; }
# Background processes (kubectl logs -f, port-forward): background commands of a script ignore SIGINT, so Ctrl-C does not stop them;
#   they are all stopped when the script exits (done, error or Ctrl-C).
BG_PIDS=()
bg_cleanup(){ local p; for p in ${BG_PIDS[@]+"${BG_PIDS[@]}"}; do kill "$p" 2>/dev/null; done
  if [ "$GW_TEL_ON" = 1 ]; then   # the hops step stopped halfway (error, Ctrl-C): still remove the temporary Telemetry, record it
    gw_accesslog_off "$GW_AL_OUT" "hops step stopped halfway"
    echo "   hops: $(date -Iseconds) Telemetry $GWN/$GW_TEL removed (hops step stopped halfway)" >> "$MANIFEST"
  fi
  [ "$TX_ON" = 1 ] && tx_mem_restore "$TX_OUT" "burst step stopped halfway"
  return 0; }
trap bg_cleanup EXIT
bg_stop(){ # $1 = background PID: stop, wait, remove from the list (a reaped PID may be reused by another process)
  local p keep=()
  kill "$1" 2>/dev/null; wait "$1" 2>/dev/null
  for p in ${BG_PIDS[@]+"${BG_PIDS[@]}"}; do [ "$p" = "$1" ] || keep+=("$p"); done
  BG_PIDS=(${keep[@]+"${keep[@]}"})
}
lt_stopped(){ # $1 = exit code of run-all-psu.sh: 129/130/143 = interrupted (HUP, Ctrl-C, TERM): stop, do not continue
  case "$1" in 129|130|143) die "run-all-psu.sh interrupted (code $1) - stopping; partial results are kept; measure the whole step again: FORCE=1 ./run-R1C7.sh $2";; esac
}

mkdir -p "$C7_DATA/jmh/params" "$C7_DATA/logs"
MANIFEST="$C7_DATA/MANIFEST.txt"
FILES=( "$BANK/run-R1C7.sh"
        "$C7_DIR/settings.gradle"
        "$C7_DIR/build.gradle"
        "$C7_DIR/src/jmh/java/bench/c7/NipokAblationBenchmark.java"
        "$C7_DIR/src/jmh/java/bench/c7/EnvelopeAblationBenchmark.java"
        "$C7_DIR/src/jmh/java/bench/c7/GatewayCerts.java"
        "$C7_DIR/src/jmh/java/bench/c7/TppCerts.java"
        "$C7_DIR/src/jmh/java/bench/c7/AuditLoggerCopy.java"
        "$C7_LT/bench-psu-auth.js"
        "$C7_LT/C7Probe.java"
        "$C7_LT/c7_hops.py"
        "$C7_LT/c7_burst.py"
        "$C7_LT/plot_loadtest.py"
        "$LT_DIR/run-all-psu.sh"
        "$LT_DIR/bench-psu-auth.js"
        "$BANK/run-R1C6.sh"
        "$E2E_DIR/run-full-e2e-nipok.sh"
        "$SCRIPTS/bench-handshake-load.sh"
        "$BANK/kubernetes/benchmark/bench_handshake_load.py"
        "$BANK/spring-cloud/authorization-server/src/main/java/sample/config/ParRequestUriGuard.java"
        "$BANK/psu-auth-spi/src/main/java/com/openbanking/psu/auth/spi/crypto/nipok/NipokEncoding.java"
        "$BANK/psu-auth-spi/src/main/java/com/openbanking/psu/auth/spi/crypto/nipok/NipokVerifier.java"
        "$BANK/psu-auth-spi/src/main/java/com/openbanking/psu/auth/spi/wallet/SimulatorWalletProvider.java"
        "$BANK/psu-auth-spi/src/main/java/com/openbanking/psu/auth/spi/mtls/XfccParser.java" )

manifest(){ # $1 = step
  { echo "== $(date -Iseconds) | step: $1 | host: $(hostname) | kernel: $(uname -r) | nproc: $(nproc)"
    local f; for f in "${FILES[@]}"; do [ -f "$f" ] && echo "   md5 $(md5sum "$f" | cut -c1-32)  ${f#$REPO/}"; done
    local j; j=$(saved_jar) && echo "   jmh jar: ${j#$REPO/} md5 $(md5sum "$j" | cut -c1-32)"
    echo "   runner: ${C7_RUNNER#$REPO/} -> $(readlink "$C7_RUNNER" 2>/dev/null || echo '<no link>') md5 $(md5sum < "$C7_RUNNER" 2>/dev/null | cut -c1-32)"
    echo "   image (v1.2): auth-server [$(img_run bank-cluster-profile "$BNS" auth-server)] customer-agent [$(img_run customer-cluster-profile customer-cluster-nsp customer-agent)]"
    echo "   clocksource: $(cat /sys/devices/system/clocksource/clocksource0/current_clocksource 2>/dev/null || echo n/a)"
    echo "   swap: $(awk '/SwapTotal/{print $2" kB"}' /proc/meminfo)"
    echo "   minikube nodes: $(docker inspect -f '{{.Name}} NanoCpus={{.HostConfig.NanoCpus}} Memory={{.HostConfig.Memory}}' \
      bank-cluster-profile customer-cluster-profile tpp-cluster-profile 2>/dev/null | tr '\n' ';' || echo n/a)"
  } >> "$MANIFEST"
}
find_build_jdk(){ # as in run-R1C6.sh: JAVA_HOME when it has javac, otherwise the JDK of javac on PATH
  local j
  if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/javac" ]; then echo "$JAVA_HOME"; return 0; fi
  j=$(command -v javac 2>/dev/null) && { dirname "$(dirname "$(readlink -f "$j")")"; return 0; }
  for j in "$HOME"/.sdkman/candidates/java/current /usr/lib/jvm/*; do [ -x "$j/bin/javac" ] && { echo "$j"; return 0; }; done
  return 1
}
jdk_major(){ "$1/bin/java" -version 2>&1 | sed -n '1s/.*version "\([0-9][0-9]*\).*/\1/p'; }
img_run(){ # $1 context $2 namespace $3 container -> imageID of the container in a Running pod (as img_ok of C6)
  kubectl --context "$1" -n "$2" get pods -o json 2>/dev/null | python3 -c '
import json, sys
c = sys.argv[1]; ids = set()
try:
    items = json.load(sys.stdin)["items"]
except Exception:
    items = []
for p in items:
    if p["status"].get("phase") != "Running" or p["metadata"].get("deletionTimestamp"):
        continue
    for s in p["status"].get("containerStatuses") or []:
        if s.get("name") == c and s.get("imageID"):
            ids.add("sha256:" + s["imageID"].split("sha256:")[-1])
print(" ".join(sorted(ids)))' "$3"
}
img_c6(){ # 0 when the auth-server and the customer-agent run the images measured in C6; prints the result
  local a g r=0
  a=$(img_run bank-cluster-profile "$BNS" auth-server); g=$(img_run customer-cluster-profile customer-cluster-nsp customer-agent)
  if [ "$a" = "$C6_IMG_AS" ]; then ok "auth-server runs the image measured in C6 (${a:0:19}...)"; else warn "auth-server: image [${a:-cannot be read}] differs from the C6 image ${C6_IMG_AS:0:19}..."; r=1; fi
  if [ "$g" = "$C6_IMG_AGENT" ]; then ok "customer-agent runs the image measured in C6 (${g:0:19}...)"; else warn "customer-agent: image [${g:-cannot be read}] differs from the C6 image ${C6_IMG_AGENT:0:19}..."; r=1; fi
  return $r
}
find_jdk24(){ # JDK >= 24 with javac (C7Probe.java runs in source-file mode; ML-DSA needs JDK 24), as find_phc_jdk of run-R1C6.sh
  local c m
  if [ -n "${PHC_JDK:-}" ]; then echo "$PHC_JDK"; return 0; fi
  for c in "$(find_build_jdk 2>/dev/null)" "$HOME"/.sdkman/candidates/java/* /usr/lib/jvm/* "$HOME"/jdks/*; do
    [ -n "$c" ] && [ -x "$c/bin/java" ] && [ -x "$c/bin/javac" ] || continue
    m=$(jdk_major "$c"); [ -n "$m" ] && [ "$m" -ge 24 ] 2>/dev/null && { echo "$c"; return 0; }
  done
  return 1
}
boot_jar(){ # auth-server bootJar (Dockerfile: ADD ./build/libs/*.jar, so exactly one file)
  local n; n=$(find "$AS_LIBS" -maxdepth 1 -name '*.jar' 2>/dev/null | wc -l)
  [ "$n" = 1 ] || return 1
  find "$AS_LIBS" -maxdepth 1 -name '*.jar'
}
boot_versions(){ # prints "nimbus=<v> tink=<v> conscrypt=<v> elisabeth=<v> psu-auth-spi=<v>" read from BOOT-INF/lib of the bootJar
  python3 - "$1" <<'PY'
import re, sys, zipfile
names = [n.rsplit("/", 1)[-1] for n in zipfile.ZipFile(sys.argv[1]).namelist() if n.startswith("BOOT-INF/lib/") and n.endswith(".jar")]
want = [("nimbus", r"nimbus-jose-jwt-(.+)\.jar"), ("tink", r"tink-(\d.*)\.jar"), ("conscrypt", r"conscrypt-openjdk-uber-(.+)\.jar"),
        ("jackson", r"jackson-databind-(.+)\.jar"),   # AuditLoggerCopy
        ("elisabeth", r"curve25519-elisabeth-(.+)\.jar"), ("psu-auth-spi", r"psu-auth-spi-(.+)\.jar")]
out = []
for key, rx in want:
    vs = sorted({m.group(1) for n in names for m in [re.fullmatch(rx, n)] if m})
    out.append("%s=%s" % (key, ",".join(vs) if vs else "?"))
print(" ".join(out))
PY
}
saved_jar(){ local x; for x in "$C7_DATA"/jmh/params/*-jmh.jar; do [ -f "$x" ] && { echo "$x"; return 0; }; done; return 1; }
jar_ok(){ # the saved jar exists and its md5 matches jmh-jar.md5
  local j w; j=$(saved_jar) || return 1
  w=$(awk 'NR==1{print $1}' "$C7_DATA/jmh/params/jmh-jar.md5" 2>/dev/null)
  [ -n "$w" ] && [ "$(md5sum "$j" | cut -c1-32)" = "$w" ]
}
c6_running(){ ps -eo pid=,args= 2>/dev/null | awk '$2 ~ /(^|\/)(ba)?sh$/ && $3 ~ /(^|\/)(run-R1C6|run-all-psu)[.]sh$/'; }
clusters_up(){ kubectl --context bank-cluster-profile get nodes >/dev/null 2>&1 \
  && kubectl --context customer-cluster-profile get nodes >/dev/null 2>&1 \
  && kubectl --context tpp-cluster-profile get nodes >/dev/null 2>&1; }
node_mem_mib(){ docker inspect "$CUST_NODE" --format '{{.HostConfig.Memory}}' 2>/dev/null | awk 'NR==1 && $1 ~ /^[0-9]+$/ {printf "%d", $1/1048576}'; }
stop_clusters(){
  local p
  for p in bank-cluster-profile tpp-cluster-profile customer-cluster-profile; do
    minikube status -p "$p" 2>/dev/null | grep -q "host: Running" && { printf '   - minikube stop -p %s\n' "$p"; minikube stop -p "$p" >/dev/null 2>&1; }
  done
  return 0
}
fresh_dir(){ # $1 = result directory; existing data stops the step (FORCE=1: rename the old copy, also the exported one)
  if [ -d "$1" ] && [ -n "$(ls -A "$1" 2>/dev/null)" ]; then
    [ "${FORCE:-0}" = 1 ] || die "$1 already holds data - check it; to measure again: FORCE=1 ./run-R1C7.sh ..."
    local sfx bak; sfx=".bak-$(date +%Y%m%d-%H%M%S)"; bak="$1$sfx"; mv "$1" "$bak"; warn "old copy renamed -> $bak"
    local ed="$EXPORT_DIR/${1#$C7_DATA/}" eb="$EXPORT_DIR/${bak#$C7_DATA/}"
    if [ -n "$EXPORT_DIR" ] && [ -d "$ed" ] && [ ! -e "$eb" ]; then mv "$ed" "$eb" && warn "exported copy renamed as well -> $eb"; fi
  fi
  mkdir -p "$1"
}
run_logged(){ local name=$1; shift; "$@" 2>&1 | tee "$C7_DATA/logs/$name.console.log"; return "${PIPESTATUS[0]}"; }

# --- e2e part: helpers ---------------------------------------------------------
runner_ok(){ # k6-psu-c7/run-all-psu.sh is a relative link to the run-all-psu.sh of C6 (same content). The link is not
  # stored in the repository (checkouts without symbolic-link support); it is created here when it does not exist.
  [ -e "$C7_RUNNER" ] || [ -L "$C7_RUNNER" ] || ln -s "$RUNNER_LINK" "$C7_RUNNER" 2>/dev/null
  [ -L "$C7_RUNNER" ] && [ "$(readlink "$C7_RUNNER")" = "$RUNNER_LINK" ] && [ -f "$LT_DIR/run-all-psu.sh" ] \
    && [ "$(md5sum < "$C7_RUNNER" | cut -c1-32)" = "$(md5sum < "$LT_DIR/run-all-psu.sh" | cut -c1-32)" ]
}
lt_common(){ # LT_COMMON and RL_UP are read from run-R1C6.sh, so the load configuration equals that of the C6 blocks
  LT_COMMON=(); RL_UP=()   # a missing line is reported clearly below instead of an "unbound variable" stop (set -u)
  local src; src=$(sed -n '/^LT_COMMON=(/,/)$/p; /^RL_UP=(/p' "$BANK/run-R1C6.sh")
  [ -n "$src" ] || die "cannot read LT_COMMON/RL_UP from $BANK/run-R1C6.sh"
  eval "$src"
  [ "${#LT_COMMON[@]}" -ge 10 ] && [ "${#RL_UP[@]}" -ge 1 ] || die "LT_COMMON/RL_UP read from run-R1C6.sh are not valid"
}
e2e_preflight(){ # common conditions of the e2e part
  [ -z "$(c6_running)" ] || die "a C6 measurement is running - wait until it ends before measuring C7"
  runner_ok || die "link ${C7_RUNNER#$REPO/} -> $RUNNER_LINK missing or wrong (create it: ln -s $RUNNER_LINK ${C7_RUNNER#$REPO/})"
  clusters_up || die "clusters are not running (start them: cd $REPO && ./up.sh)"
  local nm; nm=$(node_mem_mib)
  [ -n "$nm" ] && { [ "$nm" = 0 ] || [ "$nm" -ge "$NODE_MEM_MIN_MIB" ]; } \
    || die "node $CUST_NODE: docker memory limit ${nm:-?} MiB < $NODE_MEM_MIN_MIB - run: ./run-R1C6.sh fix-node-mem"
  [ "$(awk '/SwapTotal/{print $2}' /proc/meminfo)" = 0 ] || die "swap is on - run: sudo swapoff -a"
  [ -f "$LT_DIR/run-all-psu.sh" ] && [ -f "$C7_LT/bench-psu-auth.js" ] || die "run-all-psu.sh (C6) or k6-psu-c7 missing"
  "$BANK/run-R1C6.sh" verify-as || die "the auth-server fails verify-as (authorization store, PAR_REQUEST_URI_GUARD)"
  if ! img_c6; then   # C7 values must come from the images measured in C6
    [ "${C7_ALLOW_IMAGE_CHANGE:-0}" = 1 ] && warn "C7_ALLOW_IMAGE_CHANGE=1: measuring although the images differ from C6 (recorded in MANIFEST)" \
      || die "the pods do not run the images measured in C6 (wait until the old pods have terminated and run again; on another host set C7_ALLOW_IMAGE_CHANGE=1)"
  fi
}
envoy_ssl(){ # TLS counters of Envoy at the ingress gateway (read only); empty when Istio records no listener.*.ssl.* (as in this testbed)
  $KB -n "$GWN" exec "deploy/$GWD" -c istio-proxy -- pilot-agent request GET 'stats?filter=ssl' 2>/dev/null \
    | grep -E '^listener\.[^:]+\.ssl\.' || true
}
envoy_admin(){ # 0 when the Envoy stats of the ingress gateway can be read: server.uptime belongs to the default stats group
  # of Istio (cluster_manager, listener_manager, server, cluster.xds-grpc), so it is present whenever kubectl exec and pilot-agent work
  $KB -n "$GWN" exec "deploy/$GWD" -c istio-proxy -- pilot-agent request GET 'stats?filter=server.uptime' 2>/dev/null \
    | grep -q '^server\.uptime:'
}
gw_mesh_accesslog(){ # read only: accessLog*/defaultProviders lines of meshConfig, the Telemetry resources (accessLogging part),
  # number of file access loggers in the running Envoy configuration of the gateway (config_dump, counted only, content not printed)
  local n
  echo "meshConfig (configmap $GWN/istio):"
  $KB -n "$GWN" get cm istio -o jsonpath='{.data.mesh}' 2>/dev/null | grep -i -E -A2 'accessLog|defaultProviders' | sed 's/^/   /' \
    || echo "   (no accessLog*, defaultProviders lines)"
  echo "Telemetry (namespace/name, selector, accessLogging):"
  $KB get telemetry -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name} selector={.spec.selector.matchLabels} accessLogging={.spec.accessLogging}{"\n"}{end}' \
    2>/dev/null | grep . | sed 's/^/   /' || echo "   (none, or cannot be read)"
  if n=$($KB -n "$GWN" exec "deploy/$GWD" -c istio-proxy -- pilot-agent request GET config_dump 2>/dev/null \
      | grep -c 'envoy.extensions.access_loggers.file.v3.FileAccessLog'; exit "${PIPESTATUS[0]}"); then
    echo "Envoy of $GWD (config_dump): $n file access loggers (including loggers that record no request, e.g. that of admin; compare with the value before enabling)"
  else echo "Envoy of $GWD (config_dump): cannot be read (kubectl exec ... pilot-agent request failed)"; fi
}
gw_accesslog_probe(){ # send a marked request to the gateway and look for the mark in the gateway log; 0 when found (<= 30 s)
  local tag i; tag="c7accesslog$(date +%s%N)"
  for i in $(seq 1 "${C7_GW_PROBE_TRIES:-6}"); do
    curl -sk -o /dev/null --max-time 10 "$BANK_URL/psu/login-page?$tag=$i" >/dev/null 2>&1 || true
    sleep "${C7_GW_PROBE_WAIT:-5}"
    $KB -n "$GWN" logs "deploy/$GWD" --since=90s 2>/dev/null | grep -q "$tag" && return 0
  done
  return 1
}
gw_accesslog_gone(){ # after removing the Telemetry: 0 when a NEW marked request is no longer logged (at most C7_GW_PROBE_TRIES attempts)
  local tag i
  for i in $(seq 1 "${C7_GW_PROBE_TRIES:-6}"); do
    tag="c7accesslogoff$(date +%s%N)"
    curl -sk -o /dev/null --max-time 10 "$BANK_URL/psu/login-page?$tag=$i" >/dev/null 2>&1 || true
    sleep "${C7_GW_PROBE_WAIT:-5}"
    $KB -n "$GWN" logs "deploy/$GWD" --since=90s 2>/dev/null | grep -q "$tag" || { echo "$i"; return 0; }
  done
  return 1
}
gw_accesslog_on(){ # $1 = result directory. Enable the access log of istio-ingressgateway only (Telemetry, provider envoy)
  local out=$1 f="$1/gateway-accesslog-telemetry.yaml"
  { echo "== $(date -Iseconds) before enabling"; gw_mesh_accesslog; } >> "$out/gateway-accesslog.txt"
  if gw_accesslog_probe; then   # an existing access log: nothing is changed
    echo "== $(date -Iseconds) the gateway already writes an access log: no Telemetry applied" >> "$out/gateway-accesslog.txt"
    GW_AL_STATE="present (no Telemetry applied)"; ok "access log of $GWD: already present, configuration unchanged"; return 0
  fi
  cat > "$f" <<EOF
apiVersion: telemetry.istio.io/v1
kind: Telemetry
metadata:
  name: $GW_TEL
  namespace: $GWN
  labels:
    r1-c7: hops
spec:
  selector:
    matchLabels:
      istio: ingressgateway
  accessLogging:
  - providers:
    - name: envoy
EOF
  GW_TEL_ON=1; GW_AL_OUT=$out
  $KB apply -f "$f" >> "$out/gateway-accesslog.txt" 2>&1 \
    || { gw_accesslog_off "$out"; die "cannot apply Telemetry $GWN/$GW_TEL (see e2e/hops/gateway-accesslog.txt)"; }
  if gw_accesslog_probe; then
    { echo "== $(date -Iseconds) Telemetry $GWN/$GW_TEL applied: the marked request is in the gateway log"; gw_mesh_accesslog; } \
      >> "$out/gateway-accesslog.txt"
    GW_AL_STATE="temporary Telemetry $GWN/$GW_TEL (provider envoy, $GWD only)"; ok "access log of $GWD: enabled temporarily (Telemetry $GWN/$GW_TEL; removed at the end of the hops step)"
  else
    gw_accesslog_off "$out"
    die "Telemetry applied but the gateway still writes no access log - removed, nothing measured; see e2e/hops/gateway-accesslog.txt"
  fi
}
gw_accesslog_off(){ # $1 = result directory (empty: remove only), $2 = note. Remove the temporary Telemetry of the hops step
  local st n
  $KB -n "$GWN" delete telemetry "$GW_TEL" --ignore-not-found >/dev/null 2>&1; GW_TEL_ON=0
  if [ -n "${1:-}" ]; then   # check that the gateway has stopped logging (Envoy receives the new configuration after a few seconds)
    if n=$(gw_accesslog_gone); then st="the gateway stopped writing the access log (the marked request is no longer logged, attempt $n)"
    else st="! the gateway STILL writes the access log after ${C7_GW_PROBE_TRIES:-6} attempts"; warn "the gateway still writes the access log after the Telemetry was removed - check e2e/hops/gateway-accesslog.txt"; fi
    { echo "== $(date -Iseconds) Telemetry $GWN/$GW_TEL removed${2:+ ($2)}: $st"; gw_mesh_accesslog; } >> "$1/gateway-accesslog.txt"
  fi
  return 0
}
bak_logs(){ # FORCE=1: keep the console logs of the previous measurement (renamed *.bak-<time>), $@ = name patterns in logs/
  local pat f sfx; sfx=".bak-$(date +%Y%m%d-%H%M%S)"
  # shellcheck disable=SC2086   # $pat is a file name pattern (glob), deliberately unquoted
  for pat in "$@"; do for f in "$C7_DATA"/logs/$pat; do [ -f "$f" ] && mv "$f" "$f$sfx"; done; done
  return 0
}
mem_bytes(){ # Kubernetes memory quantity ("400Mi", "1Gi", "500M", "419430400") -> bytes; empty when it cannot be read
  python3 - "${1:-}" <<'PY'
import re, sys
m = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*(Ki|Mi|Gi|Ti|k|K|M|G|T)?\s*", sys.argv[1])
if m:
    mul = {None: 1, "k": 10**3, "K": 10**3, "M": 10**6, "G": 10**9, "T": 10**12,
           "Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40}[m.group(2)]
    print(int(float(m.group(1)) * mul))
PY
}
tx_spec(){ # transaction deployment -> "<container index><US><resources JSON><US><JAVA_TOOL_OPTIONS><US><env count>" (US = \x1f:
  # not whitespace, so empty fields are not merged by read; split with txf)
  $KB -n "$BNS" get deploy/"$TX_DEP" -o json 2>/dev/null | python3 -c '
import json, sys
try:
    cs = json.load(sys.stdin)["spec"]["template"]["spec"]["containers"]
except Exception:
    sys.exit(1)
for i, c in enumerate(cs):
    if c.get("name") == sys.argv[1]:
        env = c.get("env") or []
        jto = next((e.get("value", "") for e in env if e.get("name") == "JAVA_TOOL_OPTIONS"), "")
        print("%d\x1f%s\x1f%s\x1f%d" % (i, json.dumps(c.get("resources") or {}, sort_keys=True, separators=(",", ":")), jto, len(env)))
        sys.exit(0)
sys.exit(1)' "$TX_C"
}
txf(){ cut -d $'\x1f' -f "$1" <<< "$2"; }   # field $1 of the tx_spec line $2
tx_pods(){ # transaction pods: name, phase, ready, restarts, previous termination (reason, code), running limits.memory
  $KB -n "$BNS" get pods -l "app.kubernetes.io/name=$TX_DEP" -o json 2>/dev/null | python3 -c '
import json, sys
try:
    items = json.load(sys.stdin)["items"]
except Exception:
    items = []
for p in items:
    c = next((x for x in p["spec"].get("containers", []) if x.get("name") == sys.argv[1]), {})
    s = next((x for x in p.get("status", {}).get("containerStatuses") or [] if x.get("name") == sys.argv[1]), {})
    t = (s.get("lastState") or {}).get("terminated") or {}
    last = "%s exit %s at %s" % (t.get("reason"), t.get("exitCode"), t.get("finishedAt")) if t else "-"
    print("%s phase=%s ready=%s restarts=%s previous=%s limits.memory=%s%s" % (
        p["metadata"]["name"], p.get("status", {}).get("phase"), s.get("ready"), s.get("restartCount"), last,
        ((c.get("resources") or {}).get("limits") or {}).get("memory"),
        " (terminating)" if p["metadata"].get("deletionTimestamp") else ""))' "$TX_C"
}
tx_mem_up(){ # $1 = result directory of the burst step. Raise limits.memory of the transaction container to $TX_MEM, keeping
  # requests.memory (scheduling unchanged) and the heap sizing of the JVM (JAVA_TOOL_OPTIONS=-XX:MaxRAM=<previous limit>)
  local out=$1 sp idx res jto nenv lim req limb newb new pin="" patch sp2
  if [ "$TX_MEM" = 0 ]; then
    { echo "== $(date -Iseconds) resources of transaction unchanged (C7_TX_MEM_LIMIT=0)"; tx_pods; } >> "$out/transaction-resources.txt"
    echo "   burst: transaction unchanged (C7_TX_MEM_LIMIT=0)" >> "$MANIFEST"
    ok "transaction: resources unchanged (C7_TX_MEM_LIMIT=0)"; return 0
  fi
  sp=$(tx_spec) || die "cannot read the deployment $BNS/$TX_DEP (container $TX_C)"
  IFS=$'\x1f' read -r idx res jto nenv <<< "$sp"
  lim=$(python3 -c 'import json,sys; print((json.loads(sys.argv[1]).get("limits") or {}).get("memory", ""))' "$res")
  req=$(python3 -c 'import json,sys; print((json.loads(sys.argv[1]).get("requests") or {}).get("memory", ""))' "$res")
  [ -n "$lim" ] || die "the transaction container has no limits.memory (resources=$res)"
  [ -z "$jto" ] || die "the transaction container already has JAVA_TOOL_OPTIONS (value: $jto) - not overwritten"
  limb=$(mem_bytes "$lim"); newb=$(mem_bytes "$TX_MEM")
  [ -n "$limb" ] && [ -n "$newb" ] || die "cannot read the memory values (current $lim, C7_TX_MEM_LIMIT=$TX_MEM)"
  if [ "$newb" -le "$limb" ]; then
    { echo "== $(date -Iseconds) unchanged: C7_TX_MEM_LIMIT=$TX_MEM is not above the current limits.memory $lim"; tx_pods; } >> "$out/transaction-resources.txt"
    echo "   burst: transaction unchanged (limits.memory $lim >= C7_TX_MEM_LIMIT=$TX_MEM)" >> "$MANIFEST"
    warn "transaction: current limits.memory $lim >= $TX_MEM - unchanged"; return 0
  fi
  new=$(python3 -c 'import json,sys
r = json.loads(sys.argv[1]); r.setdefault("limits", {})["memory"] = sys.argv[2]; r.setdefault("requests", {})["memory"] = sys.argv[3]
print(json.dumps(r, sort_keys=True, separators=(",", ":")))' "$res" "$TX_MEM" "${req:-$lim}")
  patch='[{"op":"add","path":"/spec/template/spec/containers/'"$idx"'/resources","value":'"$new"'}'
  if [ "$TX_PIN" = 1 ]; then
    pin="-XX:MaxRAM=$limb"
    if [ "${nenv:-0}" -gt 0 ]; then
      patch+=',{"op":"add","path":"/spec/template/spec/containers/'"$idx"'/env/-","value":{"name":"JAVA_TOOL_OPTIONS","value":"'"$pin"'"}}'
    else
      patch+=',{"op":"add","path":"/spec/template/spec/containers/'"$idx"'/env","value":[{"name":"JAVA_TOOL_OPTIONS","value":"'"$pin"'"}]}'
    fi
  fi
  patch+=']'
  printf '%s\n' "$res" > "$out/transaction-resources.orig.json"   # original copy for the restore (also by hand: ./run-R1C7.sh tx-mem-restore)
  { echo "== $(date -Iseconds) before the change: resources=$res JAVA_TOOL_OPTIONS=<none>"; tx_pods; } >> "$out/transaction-resources.txt"
  TX_ON=1; TX_ORIG=$res; TX_OUT=$out
  $KB -n "$BNS" patch deploy/"$TX_DEP" --type=json -p "$patch" >> "$out/transaction-resources.txt" 2>&1 \
    || { tx_mem_restore "$out" "kubectl patch failed"; die "cannot change the resources of transaction (kubectl patch; see e2e/burst/transaction-resources.txt)"; }
  $KB -n "$BNS" rollout status deploy/"$TX_DEP" --timeout=300s >> "$out/transaction-resources.txt" 2>&1 \
    || { tx_mem_restore "$out" "rollout failed"; die "transaction not ready after the resource change (restored; see e2e/burst/transaction-resources.txt)"; }
  sp2=$(tx_spec) || sp2=""
  [ "$(txf 2 "$sp2")" = "$new" ] && [ "$(txf 3 "$sp2")" = "$pin" ] \
    || { tx_mem_restore "$out" "check after the change failed"; die "the transaction deployment does not match after the change ($sp2) - restored"; }
  { echo "== $(date -Iseconds) after the change: resources=$new JAVA_TOOL_OPTIONS=${pin:-<none>}"; tx_pods
    [ -n "$pin" ] && echo "   JVM log: $($KB -n "$BNS" logs deploy/"$TX_DEP" -c "$TX_C" --tail=400 2>/dev/null | grep -m1 'Picked up JAVA_TOOL_OPTIONS' || echo '(line Picked up JAVA_TOOL_OPTIONS not seen yet)')"
  } >> "$out/transaction-resources.txt"
  echo "   burst: transaction limits.memory $lim -> $TX_MEM, requests.memory ${req:-<not set, default = limits>} -> ${req:-$lim}, JAVA_TOOL_OPTIONS=${pin:-<not set>}" >> "$MANIFEST"
  ok "transaction: limits.memory $lim -> $TX_MEM (requests ${req:-$lim})${pin:+; heap as before: JAVA_TOOL_OPTIONS=$pin}; restored at the end of the step"
}
tx_mem_restore(){ # $1 = result directory (empty: e2e/burst), $2 = note. Restore the resources of transaction to the original and
  # remove the JAVA_TOOL_OPTIONS=-XX:MaxRAM=... added by C7
  local out=${1:-$C7_DATA/e2e/burst} orig=${TX_ORIG:-} sp idx res jto k patch rc=0
  [ -n "$orig" ] || { [ -s "$out/transaction-resources.orig.json" ] && orig=$(cat "$out/transaction-resources.orig.json"); }
  [ -n "$orig" ] || { warn "no original resources of transaction ($out/transaction-resources.orig.json)"; return 1; }
  sp=$(tx_spec) || { warn "cannot read the deployment $BNS/$TX_DEP - restore by hand: ./run-R1C7.sh tx-mem-restore"; return 1; }
  IFS=$'\x1f' read -r idx res jto _ <<< "$sp"
  k=$($KB -n "$BNS" get deploy/"$TX_DEP" -o json 2>/dev/null | python3 -c '
import json, sys
c = json.load(sys.stdin)["spec"]["template"]["spec"]["containers"][int(sys.argv[1])]
for j, e in enumerate(c.get("env") or []):
    if e.get("name") == "JAVA_TOOL_OPTIONS" and str(e.get("value", "")).startswith("-XX:MaxRAM="):
        print(j); break' "$idx" 2>/dev/null)
  if [ "$res" = "$orig" ] && [ -z "$k" ]; then
    TX_ON=0; [ -d "$out" ] && echo "== $(date -Iseconds) transaction already at the original${2:+ ($2)}" >> "$out/transaction-resources.txt"
    ok "transaction: already at the original resources, no restore needed${2:+ ($2)}"; return 0
  fi
  patch='[{"op":"add","path":"/spec/template/spec/containers/'"$idx"'/resources","value":'"$orig"'}'
  [ -n "$k" ] && patch+=',{"op":"remove","path":"/spec/template/spec/containers/'"$idx"'/env/'"$k"'"}'
  patch+=']'
  if $KB -n "$BNS" patch deploy/"$TX_DEP" --type=json -p "$patch" >/dev/null 2>&1; then
    TX_ON=0
    $KB -n "$BNS" rollout status deploy/"$TX_DEP" --timeout=240s >/dev/null 2>&1 || rc=2
  else rc=1; fi
  sp=$(tx_spec) || sp=""
  if [ "$rc" != 1 ] && [ "$(txf 2 "$sp")" = "$orig" ] && [ -z "$(txf 3 "$sp")" ]; then
    [ -d "$out" ] && { echo "== $(date -Iseconds) restored${2:+ ($2)}: resources=$orig, JAVA_TOOL_OPTIONS removed$([ "$rc" = 2 ] && echo '; rollout not finished after 240 s')"; tx_pods; } >> "$out/transaction-resources.txt"
    echo "   burst: $(date -Iseconds) transaction restored${2:+ ($2)}" >> "$MANIFEST"
    ok "transaction: original resources restored${2:+ ($2)}"; return 0
  fi
  [ -d "$out" ] && echo "== $(date -Iseconds) RESTORE FAILED${2:+ ($2)}: the deployment is now $sp" >> "$out/transaction-resources.txt"
  warn "the resources of transaction are not restored - run: ./run-R1C7.sh tx-mem-restore"; return 1
}
burst_valid(){ # $1 = burst directory -> prints "<valid runs> <total> <invalid list>" from burst.json (c7_burst.py)
  python3 - "$1" <<'PY'
import json, os, sys
try:
    d = json.load(open(os.path.join(sys.argv[1], "burst.json"), encoding="utf-8"))
except Exception:
    print("0 0 -"); sys.exit(0)
ok = tot = 0; bad = []
for mech, v in sorted(d.items()):
    for r in v.get("runs", []):
        tot += 1
        if r.get("valid", True):
            ok += 1
        else:
            bad.append("%s-r%s" % (mech, r.get("rep")))
print(ok, tot, ",".join(bad) or "-")
PY
}
actuator_prom(){ # /actuator/prometheus of the auth-server through port-forward (not through the sidecar); printed to stdout
  local pf _
  $KB -n "$BNS" port-forward deploy/auth-server "$PF_PORT:80" >/dev/null 2>&1 &
  pf=$!; BG_PIDS+=("$pf")
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    curl -s --max-time 5 "http://127.0.0.1:$PF_PORT/actuator/prometheus" 2>/dev/null && break
    sleep 1
  done
  bg_stop "$pf"
  return 0
}
as_pods(){ # auth-server pods: name, start time, status (tells whether the Prometheus counters are continuous between two reads)
  $KB -n "$BNS" get pods --no-headers -o custom-columns='NAME:.metadata.name,START:.status.startTime,PHASE:.status.phase' 2>/dev/null \
    | awk '$1 ~ /^auth-server-/' || true
}
gw_info(){ # $1 = PEM -> "DER <n> bytes, cb <base64url(SHA-256(DER))>" of the first certificate (leaf)
  python3 - "$1" <<'PY'
import base64, hashlib, re, ssl, sys
m = re.search(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", open(sys.argv[1], encoding="ascii", errors="replace").read(), re.S)
der = ssl.PEM_cert_to_DER_cert(m.group(0)) if m else b""
print("DER %d bytes, cb %s" % (len(der), base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode()) if der else "cannot read the certificate")
PY
}
deploy_env(){ # value of an environment variable of the auth-server container (not printed to the screen)
  $KB -n "$BNS" get deploy/auth-server -o jsonpath="{.spec.template.spec.containers[?(@.name==\"auth-server\")].env[?(@.name==\"$1\")].value}" 2>/dev/null
}
rl_want(){ # prints "<psu> <par>" from RL_UP of run-R1C6.sh (RL_PSU=..., RL_PAR=...); called after lt_common
  local x psu="" par=""
  for x in "${RL_UP[@]}"; do
    case "$x" in RL_PSU=*) psu=${x#RL_PSU=} ;; RL_PAR=*) par=${x#RL_PAR=} ;; esac
  done
  [[ "$psu" =~ ^[0-9]+$ && "$par" =~ ^[0-9]+$ ]] || return 1
  echo "$psu $par"
}
rl_ensure(){ # $1 = result directory of the step. auth-server rate limiter = RL_UP of run-R1C6.sh (as in C6); writes rate-limiter.txt
  local d=$1 want psu par bpsu bpar apsu apar act="unchanged"
  lt_common
  want=$(rl_want) || die "RL_UP of run-R1C6.sh has no numeric RL_PSU/RL_PAR - cannot set the rate limiter as in C6"
  read -r psu par <<< "$want"
  bpsu=$(deploy_env APP_RATELIMIT_PSU_PER_SEC); bpar=$(deploy_env APP_RATELIMIT_PAR_PER_SEC)
  if [ "$bpsu" != "$psu" ] || [ "$bpar" != "$par" ]; then
    act="reset"
    $KB -n "$BNS" set env deploy/auth-server "APP_RATELIMIT_PSU_PER_SEC=$psu" "APP_RATELIMIT_PAR_PER_SEC=$par" >/dev/null 2>&1 \
      || die "cannot set the rate limiter of the auth-server (kubectl set env)"
    $KB -n "$BNS" rollout status deploy/auth-server --timeout=180s >/dev/null 2>&1 \
      || die "the auth-server is not ready after setting the rate limiter (kubectl rollout status)"
    "$BANK/run-R1C6.sh" verify-as || die "the auth-server fails verify-as after setting the rate limiter"
  fi
  apsu=$(deploy_env APP_RATELIMIT_PSU_PER_SEC); apar=$(deploy_env APP_RATELIMIT_PAR_PER_SEC)
  [ "$apsu" = "$psu" ] && [ "$apar" = "$par" ] \
    || die "the rate limiter of the auth-server is PSU=${apsu:-?} PAR=${apar:-?}, not $psu/$par as in C6"
  printf '%s | %s | before: PSU=%s PAR=%s | used: PSU=%s PAR=%s req/s per IP (RL_UP of run-R1C6.sh, as in C6)\n' "$(date -Iseconds)" \
    "$act" "${bpsu:-<not set, Helm default>}" "${bpar:-<not set, Helm default>}" "$apsu" "$apar" >> "$d/rate-limiter.txt"
  if [ "$act" = "unchanged" ]; then ok "auth-server rate limiter: PSU=$apsu PAR=$apar req/s per IP (as in C6)"
  else ok "auth-server rate limiter: PSU=$apsu PAR=$apar req/s per IP (reset as in C6; before PSU=${bpsu:-default} PAR=${bpar:-default})"; fi
}
run_lt(){ # $1 = result directory, $2 = log, the rest = environment for run-all-psu.sh (after LT_COMMON and RL_UP)
  local d=$1 name=$2 extra pj pc; shift 2
  # PHC tool as in lt_run of run-R1C6.sh (run-all-psu.sh needs it only when the PHC of pwd-1 is not at the default, e.g. after
  # a run stopped inside password_owasp); PHC_TOOL must be explicit because the DIR of run-all-psu.sh is k6-psu-c7 (called through the link).
  extra=(PHC_TOOL="$LT_DIR/R1C6PhcTool.java")
  pj=$(find_jdk24 2>/dev/null) && extra+=(PHC_JAVA="$pj/bin/java")
  for pc in "$BANK"/benchmark-R1-C6/jmh/params/*-jmh.jar "$BANK"/benchmark/crypto-jmh/build/libs/*-jmh.jar; do
    [ -f "$pc" ] && { extra+=(PHC_CP="$pc"); break; }
  done
  runner_ok || die "link ${C7_RUNNER#$REPO/} -> $RUNNER_LINK missing or wrong"
  ( cd "$C7_LT" && env "${LT_COMMON[@]}" "${RL_UP[@]}" RESULTS="$d" "${extra[@]}" "$@" \
      "$C7_RUNNER" ) 2>&1 | tee "$C7_DATA/logs/$name.console.log"   # through the link, so DIR = k6-psu-c7
  return "${PIPESTATUS[0]}"
}

# --- commands ----------------------------------------------------------------
check(){
  say "[check] files of C7 and the C6 files it uses"
  local f; for f in "${FILES[@]}"; do [ -f "$f" ] && ok "$(md5sum "$f" | cut -c1-32)  ${f#$REPO/}" || warn "MISSING ${f#$REPO/}"; done
  if runner_ok; then ok "${C7_RUNNER#$REPO/} -> $RUNNER_LINK ($(md5sum < "$C7_RUNNER" | cut -c1-32)): run-all-psu.sh uses the k6 scenarios of C7"
  else warn "link ${C7_RUNNER#$REPO/} -> $RUNNER_LINK missing or wrong (create it: ln -s $RUNNER_LINK ${C7_RUNNER#$REPO/})"; fi
  [ -x "$C7_DIR/gradlew" ] && [ -f "$C7_DIR/gradle/wrapper/gradle-wrapper.jar" ] \
    && ok "Gradle wrapper: $(sed -n 's/^distributionUrl=.*gradle-\(.*\)-bin.zip/\1/p' "$C7_DIR/gradle/wrapper/gradle-wrapper.properties")" \
    || warn "Gradle wrapper missing in $C7_DIR"
  if ( lt_common ) >/dev/null 2>&1; then ok "LT_COMMON and RL_UP readable from run-R1C6.sh"; else warn "cannot read LT_COMMON/RL_UP from run-R1C6.sh"; fi
  say "[check] JVM"
  [ -x "$TEMURIN_JRE/bin/java" ] && ok "Temurin for JMH: $("$TEMURIN_JRE/bin/java" -version 2>&1 | grep -m1 Runtime)" || warn "$TEMURIN_JRE not found (./run-R1C6.sh setup-jvm)"
  find_build_jdk >/dev/null && ok "build JDK: $(find_build_jdk)" || warn "no JDK with javac found"
  find_jdk24 >/dev/null && ok "JDK >= 24 for C7Probe: $(find_jdk24)" || warn "no JDK >= 24 with javac found (needed by probe)"
  say "[check] auth-server bootJar (library versions for crypto-jmh-c7)"
  local bj; if bj=$(boot_jar); then ok "${bj#$REPO/}: $(boot_versions "$bj")"; else warn "not exactly one jar in ${AS_LIBS#$REPO/} (run ./run-R1C6.sh redeploy-as first)"; fi
  say "[check] saved JMH jar"
  local j; if j=$(saved_jar); then
    if jar_ok; then ok "${j#$REPO/} md5 $(md5sum "$j" | cut -c1-32) (matches jmh-jar.md5)"; else warn "${j#$REPO/}: md5 does not match jmh-jar.md5"; fi
    [ -f "$C7_DATA/jmh/params/build.txt" ] && sed 's/^/   /' "$C7_DATA/jmh/params/build.txt"
  else warn "no jar yet (./run-R1C7.sh build)"; fi
  if [ -s "$C7_DATA/e2e/probe/gateway.pem" ]; then ok "jmh computes cb on the actual gateway certificate e2e/probe/gateway.pem ($(gw_info "$C7_DATA/e2e/probe/gateway.pem"))"
  else echo "   jmh computes cb on the bundled ecdsa-p256 test certificate (no e2e/probe/gateway.pem yet: run probe before jmh)"; fi
  say "[check] clusters and tools for the e2e part"
  [ -z "$(c6_running)" ] && ok "no C6 measurement running" || warn "a C6 measurement IS running - do not build/measure C7 now"
  if clusters_up; then
    ok "three clusters running"
    img_c6 || true
    if [ -n "$(envoy_ssl | head -1)" ]; then ok "Envoy TLS counters of $GWD readable (listener.*.ssl.*)"
    elif envoy_admin; then   # expected state of the testbed: Istio records only the default stats group
      ok "Envoy stats of $GWD readable (pilot-agent request GET stats)"
      echo "   the Istio of the testbed records no TLS listener counters listener.*.ssl.* (default stats group only), so hops counts TLS connections per journey from the access log (expected, not an error)"
    else warn "cannot read the Envoy stats of $GWD (kubectl exec ... pilot-agent request failed)"; fi
    if actuator_prom | grep -q '^auth_server_ed25519_sign_seconds'; then ok "auth_server_ed25519_sign_seconds readable through port-forward :$PF_PORT"
    else warn "cannot read /actuator/prometheus of the auth-server through port-forward :$PF_PORT"; fi
    local rlw rp ra cp ca
    if rlw=$( ( lt_common && rl_want ) 2>/dev/null ); then
      read -r rp ra <<< "$rlw"; cp=$(deploy_env APP_RATELIMIT_PSU_PER_SEC); ca=$(deploy_env APP_RATELIMIT_PAR_PER_SEC)
      if [ "$cp" = "$rp" ] && [ "$ca" = "$ra" ]; then ok "auth-server rate limiter: PSU=$cp PAR=$ca req/s per IP (= RL_UP of run-R1C6.sh, as in C6)"
      else warn "auth-server rate limiter: PSU=${cp:-default} PAR=${ca:-default}, differs from RL_UP ($rp/$ra) - hops, burst, probe and tls reset it as in C6"; fi
    else warn "cannot read RL_PSU/RL_PAR of RL_UP in run-R1C6.sh"; fi
    local txs; if txs=$(tx_spec); then
      ok "transaction: resources=$(txf 2 "$txs") JAVA_TOOL_OPTIONS=$(txf 3 "$txs" | sed 's/^$/<none>/')"
      [ -s "$C7_DATA/e2e/burst/transaction-resources.orig.json" ] && [ "$(txf 2 "$txs")" != "$(cat "$C7_DATA/e2e/burst/transaction-resources.orig.json")" ] \
        && warn "transaction DIFFERS from the original in e2e/burst/transaction-resources.orig.json (burst step stopped halfway?) - run: ./run-R1C7.sh tx-mem-restore"
    else warn "cannot read the deployment $BNS/$TX_DEP"; fi
    tx_pods | sed 's/^/   /'
  else warn "clusters stopped (hops/burst/probe/tls need them; jmh and smoke do not)"; fi
  getent hosts bank.openbanking.dev >/dev/null && ok "bank.openbanking.dev -> $(getent hosts bank.openbanking.dev | awk '{print $1; exit}')" \
    || warn "bank.openbanking.dev does not resolve (probe needs the line '127.0.0.1 bank.openbanking.dev' in /etc/hosts)"
  command -v jq >/dev/null && ok "jq: $(jq --version)" || warn "jq not found (the tls step needs it: sudo apt-get install -y jq)"
  command -v k6 >/dev/null && ok "k6: $(k6 version 2>/dev/null | head -1)" || warn "k6 not found"
  echo "   swap: $(awk '/SwapTotal/{print $2" kB"}' /proc/meminfo) (must be 0 kB during measurements: sudo swapoff -a)"
}

build(){
  say "[build] JMH jar of crypto-jmh-c7"
  [ -z "$(c6_running)" ] || die "a C6 measurement is running - wait until it ends before building"
  [ -x "$C7_DIR/gradlew" ] || die "$C7_DIR/gradlew not found"
  local bj vers nv tv cv jb v; bj=$(boot_jar) || die "not exactly one jar in $AS_LIBS (run ./run-R1C6.sh redeploy-as first)"
  vers=$(boot_versions "$bj"); echo "   bootJar ${bj#$REPO/}: $vers"
  nv=$(sed -n 's/.*nimbus=\([^ ]*\).*/\1/p' <<<"$vers"); tv=$(sed -n 's/.* tink=\([^ ]*\).*/\1/p' <<<"$vers")
  cv=$(sed -n 's/.*conscrypt=\([^ ]*\).*/\1/p' <<<"$vers"); local kv; kv=$(sed -n 's/.*jackson=\([^ ]*\).*/\1/p' <<<"$vers")
  for v in "$nv" "$tv" "$cv" "$kv"; do case "$v" in ""|"?"|*,*) die "cannot read exactly one version of Nimbus/Tink/Conscrypt/Jackson from the bootJar: $vers";; esac; done
  jb=$(find_build_jdk) || die "no JDK with javac found (set JAVA_HOME)"
  if saved_jar >/dev/null; then
    [ "${FORCE:-0}" = 1 ] || die "jmh/params already holds a jar - to build again: FORCE=1 ./run-R1C7.sh build"
    local sfx x; sfx=".bak-$(date +%Y%m%d-%H%M%S)"
    for x in "$C7_DATA"/jmh/params/*-jmh.jar "$C7_DATA/jmh/params/jmh-jar.md5" "$C7_DATA/jmh/params/build.txt"; do
      [ -f "$x" ] && mv "$x" "$x$sfx" && warn "renamed: ${x#$C7_DATA/} -> ${x#$C7_DATA/}$sfx"
    done
  fi
  manifest build
  { echo "build: $(date -Iseconds)"; echo "JAVA_HOME (build): $jb"; "$jb/bin/java" -version 2>&1
    echo "bootJar: ${bj#$REPO/} md5 $(md5sum "$bj" | cut -c1-32)"; echo "bootJar BOOT-INF/lib: $vers"
    echo "gradle: -PnimbusVersion=$nv -PtinkVersion=$tv -PconscryptVersion=$cv -PjacksonVersion=$kv"; } > "$C7_DATA/jmh/params/build.txt"
  ( cd "$BANK" && JAVA_HOME="$jb" run_logged build-spi ./gradlew :psu-auth-spi:publishToMavenLocal -q ) || die "publishing psu-auth-spi failed"
  ( cd "$C7_DIR" && JAVA_HOME="$jb" run_logged build ./gradlew clean jmhJar c7Versions --no-daemon -q \
      -PnimbusVersion="$nv" -PtinkVersion="$tv" -PconscryptVersion="$cv" -PjacksonVersion="$kv" ) || die "building crypto-jmh-c7 failed (see logs/build.console.log)"
  local j; j=$(find "$C7_DIR/build/libs" -maxdepth 1 -name '*-jmh.jar' | head -1); [ -n "$j" ] || die "build/libs/*-jmh.jar not found"
  cp -p "$j" "$C7_DATA/jmh/params/" || die "cannot copy the jar"
  ( cd "$C7_DATA/.." && md5sum "${C7_DATA##*/}/jmh/params/$(basename "$j")" ) > "$C7_DATA/jmh/params/jmh-jar.md5"
  grep -h 'C7_VERSIONS' "$C7_DATA/logs/build.console.log" >> "$C7_DATA/jmh/params/build.txt"
  ( cd "$BANK" && JAVA_HOME="$jb" ./gradlew --stop -q ); ( cd "$C7_DIR" && JAVA_HOME="$jb" ./gradlew --stop -q )
  ok "jar: ${C7_DATA#$REPO/}/jmh/params/$(basename "$j") md5 $(awk 'NR==1{print $1}' "$C7_DATA/jmh/params/jmh-jar.md5")"
  sed 's/^/   /' "$C7_DATA/jmh/params/build.txt"
}

jvm_run(){ # run the saved JMH jar with Temurin 24+36; the remaining arguments = JMH arguments
  local j; j=$(saved_jar) || die "no jar yet (./run-R1C7.sh build)"
  jar_ok || die "md5 of $j does not match jmh/params/jmh-jar.md5 - build again: FORCE=1 ./run-R1C7.sh build"
  [ -x "$TEMURIN_JRE/bin/java" ] || die "$TEMURIN_JRE not found - run: ./run-R1C6.sh setup-jvm"
  "$TEMURIN_JRE/bin/java" "$JVM_FLAGS" -jar "$j" "$@"
}

smoke_tools(){ # early check of the e2e tools: no cluster, no measurement, nothing written into the code directories
  local jdk tmp j
  say "[smoke] C7Probe.java compiles; the burst scenario runs with the real k6; c7_hops.py and c7_burst.py have valid syntax"
  jdk=$(find_jdk24) || die "no JDK >= 24 with javac found (needed by probe)"
  j=$(saved_jar) && jar_ok || die "no valid jar (./run-R1C7.sh build)"
  tmp=$(mktemp -d)
  "$jdk/bin/javac" -nowarn -cp "$j" -d "$tmp/cls" "$C7_LT/C7Probe.java" > "$C7_DATA/logs/smoke-probe-javac.console.log" 2>&1 \
    || { rm -rf "$tmp"; die "compiling C7Probe.java failed (logs/smoke-probe-javac.console.log)"; }
  ok "C7Probe.java compiles with the saved jar (JDK $(jdk_major "$jdk"))"
  command -v k6 >/dev/null || { rm -rf "$tmp"; die "k6 not found"; }
  # 2 + 1 + 2 s, AGENT_URL to a closed port (127.0.0.1:9): every journey fails at once, the agent is not called; k6 returns a
  # non-zero code because the threshold journey_success count>0 is not met; only the c7 fields of the summary are checked.
  ( cd "$C7_LT" && k6 run --quiet --no-usage-report -e C7_MODE=burst -e BENCH_SCENARIO=sub_saturation -e MECH=smoke \
      -e C7_BURST_PRE=2 -e C7_BURST_LEN=1 -e C7_BURST_POST=2 -e AGENT_URL=http://127.0.0.1:9/agent/run -e REQ_TIMEOUT=2s \
      -e SUMMARY_OUT="$tmp/burst-smoke.summary.json" bench-psu-auth.js ) > "$C7_DATA/logs/smoke-k6-burst.console.log" 2>&1
  python3 - "$tmp/burst-smoke.summary.json" <<'PY' || { rm -rf "$tmp"; die "the k6 burst scenario did not produce a valid summary (logs/smoke-k6-burst.console.log)"; }
import json, sys
c = json.load(open(sys.argv[1]))["c7"]
assert set(c["phases"]) == {"pre", "burst", "post"} and len(c["buckets"]) == 7 and "p99_ms" in c["buckets"][0], c
print("   [ok] k6: the burst scenario runs, the summary has 3 phases and %d buckets of 5 s (with p99)" % len(c["buckets"]))
PY
  python3 -c 'import ast, sys; [ast.parse(open(f, encoding="utf-8").read(), f) for f in sys.argv[1:]]' \
    "$C7_LT/c7_hops.py" "$C7_LT/c7_burst.py" || { rm -rf "$tmp"; die "syntax error in c7_hops.py or c7_burst.py"; }
  ok "c7_hops.py, c7_burst.py: syntax valid"
  rm -rf "$tmp"
}

smoke(){
  say "[smoke] one short run of every benchmark: correctness gate of NipokAblationBenchmark and EnvelopeAblationBenchmark"
  [ -z "$(c6_running)" ] || die "a C6 measurement is running - wait until it ends before the smoke test"
  manifest smoke
  smoke_tools
  run_logged smoke-nipok jvm_run 'bench\.c7\.NipokAblationBenchmark\..*' -f 1 -wi 0 -i 1 -r 200ms -foe true \
      -p shaProvider=default,Conscrypt \
    || die "smoke NipokAblationBenchmark failed: correctness gate not met or benchmark error (see logs/smoke-nipok.console.log)"
  run_logged smoke-envelope jvm_run 'bench\.c7\.EnvelopeAblationBenchmark\..*' -f 1 -wi 0 -i 1 -r 200ms -foe true \
    || die "smoke EnvelopeAblationBenchmark failed: correctness gate not met or benchmark error (see logs/smoke-envelope.console.log)"
  grep -h -E 'R1-C7 (envelope|audit):' "$C7_DATA/logs/smoke-envelope.console.log" | sort -u | sed 's/^/   /'
  ok "smoke PASSED: every benchmark runs, every correctness gate is met"
}

jmh(){
  say "[jmh] JMH cost breakdown -> $C7_DATA/jmh/ablation"
  [ -z "$(c6_running)" ] || die "a C6 measurement is running - wait until it ends before measuring"
  jar_ok || die "no valid jar (./run-R1C7.sh build)"
  [ -x "$TEMURIN_JRE/bin/java" ] || die "$TEMURIN_JRE not found - run: ./run-R1C6.sh setup-jvm"
  [ "$(awk '/SwapTotal/{print $2}' /proc/meminfo)" = 0 ] || die "swap is on - run: sudo swapoff -a"
  local out="$C7_DATA/jmh/ablation" jar; jar=$(saved_jar)
  # cb of the agent = SHA-256(DER of the gateway certificate): the actual certificate saved by the probe step when present,
  # otherwise the bundled ecdsa-p256 test certificate (same algorithm as the testbed default)
  local gwp="$C7_DATA/e2e/probe/gateway.pem" gwc="ecdsa-p256" gwi="bundled test certificate of GatewayCerts"
  if [ -s "$gwp" ]; then gwc="file:$gwp"; gwi=$(gw_info "$gwp"); fi
  echo "   gatewayCert: $gwc ($gwi)"
  fresh_dir "$out"
  [ "$J_ISOLATE" = 1 ] && stop_clusters
  manifest jmh
  # JMH forks inherit the JVM flags of the main process (--enable-native-access=ALL-UNNAMED), as in the main JMH of Comment 6
  local common=(-f "$J_FORKS" -wi "$J_WI" -w 1s -i "$J_IT" -r 1s -tu us -bm avgt -prof gc)
  { echo "start: $(date -Iseconds)"; echo "jar: $jar md5 $(md5sum "$jar" | cut -c1-32)"
    echo "jvm: $("$TEMURIN_JRE/bin/java" -version 2>&1 | grep -m1 Runtime)"; echo "taskset: $J_CPUS"
    echo "jmh: ${common[*]}"; echo "gatewayCert: $gwc ($gwi)"; echo "clusters_stopped: $J_ISOLATE"; } > "$out/env.txt"
  # (1) agent side: JCA SHA-512 as in the customer-agent, so shaProvider=default only
  run_logged jmh-agent taskset -c "$J_CPUS" "$TEMURIN_JRE/bin/java" "$JVM_FLAGS" -jar "$jar" \
    'bench\.c7\.NipokAblationBenchmark\.agent_.*' -p shaProvider=default -p gatewayCert="$gwc" "${common[@]}" \
    -rf json -rff "$out/nipok-agent.json" || die "agent-side JMH failed (logs/jmh-agent.console.log)"
  # (2) auth-server side and key registration: Conscrypt (auth-server configuration) and default (as in the main JMH of Comment 6)
  run_logged jmh-as taskset -c "$J_CPUS" "$TEMURIN_JRE/bin/java" "$JVM_FLAGS" -jar "$jar" \
    'bench\.c7\.NipokAblationBenchmark\.(as|reg)_.*' -p shaProvider=Conscrypt,default -p gatewayCert="$gwc" "${common[@]}" \
    -rf json -rff "$out/nipok-as.json" || die "auth-server-side JMH failed (logs/jmh-as.console.log)"
  # (3) security envelope: token, JARM, XFCC, cnf binding
  run_logged jmh-envelope taskset -c "$J_CPUS" "$TEMURIN_JRE/bin/java" "$JVM_FLAGS" -jar "$jar" \
    'bench\.c7\.EnvelopeAblationBenchmark\..*' "${common[@]}" -rf json -rff "$out/envelope.json" \
    || die "security-envelope JMH failed (logs/jmh-envelope.console.log)"
  echo "end: $(date -Iseconds)" >> "$out/env.txt"
  ok "done: $out (nipok-agent.json, nipok-as.json, envelope.json)"
  warn "C7 JMH done - start the clusters again if needed: cd $REPO && ./up.sh"
}

hops(){
  say "[hops] time of every stage at the gateway: ${M7//,/ } - fixed 8 journeys/s, $C7_REPEATS x 60 s per mechanism"
  e2e_preflight; lt_common
  local out="$C7_DATA/e2e/hops" m d lp ngw rc
  ngw=$($KB -n "$GWN" get pods -l istio=ingressgateway --no-headers 2>/dev/null | wc -l)
  [ "$ngw" = 1 ] || warn "istio-ingressgateway has $ngw pods - the access log is read from one pod only (deploy/$GWD)"
  fresh_dir "$out"; fresh_dir "$C7_DATA/e2e/istio"; manifest hops   # a new measurement also keeps the old Istio copy
  [ "${FORCE:-0}" = 1 ] && bak_logs 'hops-*.console.log' 'istio-hops-*.console.log'
  rl_ensure "$out"
  if [ "$GW_ACCESSLOG" = 1 ]; then gw_accesslog_on "$out"; else GW_AL_STATE="not enabled (C7_GW_ACCESSLOG=0)"; fi
  echo "   hops: access log of $GWD: $GW_AL_STATE" >> "$MANIFEST"
  local nempty=0
  for m in ${M7//,/ }; do
    d="$out/$m"; mkdir -p "$d"
    say "[hops] $m"
    $KB -n "$GWN" get pods -l istio=ingressgateway -o name > "$d/gateway-pods-before.txt" 2>/dev/null
    envoy_ssl > "$d/envoy-ssl-before.txt"
    as_pods > "$d/auth-server-pods-before.txt"
    actuator_prom > "$d/auth-server-prometheus-before.txt"   # counters accumulate since the pod started, so a copy before is subtracted
    $KB -n "$GWN" logs -f "deploy/$GWD" --since=1s > "$d/gateway-access.log" 2> "$d/gateway-access.err" &
    lp=$!; BG_PIDS+=("$lp")
    # RESTORE=0: no auth-server rollout at the end, so the signing metric of the measured pod can be read
    run_lt "$d" "hops-$m" RUN_LABEL="c7-hops" MECHS="$m" L8_ONLY=1 RTT_MECHS="$m" RTT_LIST=0 RTT_REPEATS="$C7_REPEATS" \
      L8_FIXED_RATE=8 DURATION=60s RESTORE=0
    rc=$?; lt_stopped "$rc" hops
    [ "$rc" = 0 ] || warn "run-all-psu.sh returned error code $rc ($m) - see logs/hops-$m.console.log"
    envoy_ssl > "$d/envoy-ssl-after.txt"
    actuator_prom > "$d/auth-server-prometheus.txt"
    as_pods > "$d/auth-server-pods-after.txt"
    bg_stop "$lp"
    $KB -n "$GWN" get pods -l istio=ingressgateway -o name > "$d/gateway-pods-after.txt" 2>/dev/null
    if ! grep -q -E '^(\{|\[)' "$d/gateway-access.log" 2>/dev/null; then   # access log lines: JSON or TEXT format of Envoy
      nempty=$((nempty + 1)); warn "$m: gateway-access.log has no access-log line (see gateway-access.err)"
    fi
    cmp -s "$d/gateway-pods-before.txt" "$d/gateway-pods-after.txt" || warn "$m: the ingress gateway pod changed during the run - the access log may be incomplete"
    grep -q '^auth_server_ed25519_sign_seconds' "$d/auth-server-prometheus.txt" || warn "$m: cannot read the token-signing metric"
    if [ -n "$ISTIO" ] && [ -f "$ISTIO" ]; then
      python3 "$ISTIO" "$d" --out "$C7_DATA/e2e/istio/hops-$m" > "$C7_DATA/logs/istio-hops-$m.console.log" 2>&1 \
        || warn "$m: istio_hops.py failed (logs/istio-hops-$m.console.log)"
    fi
  done
  [ "$GW_TEL_ON" = 1 ] && { gw_accesslog_off "$out"; ok "Telemetry $GWN/$GW_TEL removed (gateway back to the configuration of C6)"
    echo "   hops: $(date -Iseconds) Telemetry $GWN/$GW_TEL removed" >> "$MANIFEST"; }
  python3 "$C7_LT/c7_hops.py" "$out" 2>&1 | tee "$C7_DATA/logs/hops-report.console.log"
  [ "$nempty" = 0 ] || warn "hops: $nempty mechanisms have no gateway access log - see e2e/hops/gateway-accesslog.txt"
  ok "done: $out (hops.txt, hops.json)"
}

burst(){
  say "[burst] burst ${C7_BURST_BASE:-8} -> ${C7_BURST_PEAK:-64} -> ${C7_BURST_BASE:-8} journeys/s: ${M7//,/ } - $C7_REPEATS runs per mechanism"
  e2e_preflight; lt_common
  local out="$C7_DATA/e2e/burst" rc
  fresh_dir "$out"; manifest burst
  [ "${FORCE:-0}" = 1 ] && bak_logs 'burst.console.log' 'burst-report.console.log'
  rl_ensure "$out"
  tx_mem_up "$out"
  run_lt "$out" burst RUN_LABEL="c7-burst" MECHS="$M7" L8_ONLY=1 RTT_MECHS="$M7" RTT_LIST=0 RTT_REPEATS="$C7_REPEATS" \
    L8_FIXED_RATE="${C7_BURST_BASE:-8}" DURATION=180s C7_MODE=burst
  rc=$?; lt_stopped "$rc" burst
  [ "$rc" = 0 ] || warn "run-all-psu.sh returned error code $rc - see logs/burst.console.log"
  { echo "== $(date -Iseconds) end of the step, before the restore"; tx_pods; } >> "$out/transaction-resources.txt"
  [ "$TX_ON" = 1 ] && tx_mem_restore "$out" "burst step done"
  python3 "$C7_LT/c7_burst.py" "$out" 2>&1 | tee "$C7_DATA/logs/burst-report.console.log"
  local brc=${PIPESTATUS[0]} nb want   # check: every measured run must be a burst run (summary.json has c7.mode = burst)
  nb=$(burst_runs "$out")
  want=$(( $(tr ',' '\n' <<<"$M7" | grep -c .) * C7_REPEATS ))
  [ "${nb:-0}" -gt 0 ] && [ "$brc" = 0 ] \
    || die "burst: no burst run at all (summary.json has no c7) - the data cannot be used; see logs/burst.console.log"
  [ "$nb" = "$want" ] || warn "burst: only $nb/$want runs are burst runs - see logs/burst.console.log"
  local nv ntot nbad; read -r nv ntot nbad <<< "$(burst_valid "$out")"   # valid runs according to c7_burst.py
  [ "$nbad" = "-" ] || warn "burst: $((ntot - nv))/$ntot runs are NOT valid ($nbad; reasons in burst.txt) - see e2e/burst/burst.txt"
  ok "done: $out (burst.txt, burst.json; $nb/$want burst runs, $nv/$ntot valid)"
}

burst_runs(){ # $1 = burst directory -> number of summary.json with c7.mode = burst (actual burst runs)
  python3 - "$1" <<'PY'
import glob, json, sys
n = 0
for f in glob.glob(sys.argv[1] + "/*-rtt0-r*.summary.json"):
    try:
        n += (json.load(open(f)).get("c7") or {}).get("mode") == "burst"
    except Exception:
        pass
print(n)
PY
}
probe_reasons(){ # $1 = auth-server log (filtered), $2 = result file: outcome lines per probe PSU (name c7probe-<class>-<run>)
  python3 - "$1" <<'PY' | tee "$2"
import collections, re, sys
c = collections.Counter()
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    m = re.search(r"NIPOK_AUTH user=(c7probe-[A-Za-z0-9-]+?)-[0-9]{9,} .*?outcome=([a-z_]+)", line)
    if m:
        c[(m.group(1), m.group(2))] += 1
    elif "c7probe-" in line and ("PSU_LOCKOUT" in line or "account_locked" in line):
        u = re.search(r"(c7probe-[A-Za-z0-9-]+?)-[0-9]{9,}", line)
        c[(u.group(1) if u else "?", "lockout_log")] += 1
print("   %-34s %-26s %s" % ("probe PSU (class)", "outcome (NIPOK_AUTH)", "lines"))
for (u, o), n in sorted(c.items()):
    print("   %-34s %-26s %d" % (u, o, n))
print("   (bad_length, bad_encoding, noncanonical_s and a revoked PSU (nipok_no_credential) are rejected BEFORE the NIPOK_AUTH line, so no line is expected)")
PY
}

probe(){
  say "[probe] registration (seven methods), NIPoK failure classes, lockout, key lifecycle, concurrent authentication, auth-server restart"
  e2e_preflight
  local out="$C7_DATA/e2e/probe" jdk jar
  jdk=$(find_jdk24) || die "no JDK >= 24 with javac found"
  jar=$(saved_jar) && jar_ok || die "no valid jar (./run-R1C7.sh build)"
  getent hosts bank.openbanking.dev >/dev/null || die "bank.openbanking.dev does not resolve (add '127.0.0.1 bank.openbanking.dev' to /etc/hosts)"
  fresh_dir "$out"; manifest probe
  say "[probe] (1) set the auth-server and the agent to NIPoK (run-full-e2e-nipok.sh, as in the setup of C6)"
  ( cd "$E2E_DIR" && bash ./run-full-e2e-nipok.sh ) > "$out/setup-nipok.log" 2>&1
  grep -q 'NIPoK PASS' "$out/setup-nipok.log" || die "NIPoK setup failed (see e2e/probe/setup-nipok.log)"
  ok "NIPoK active, check journey HTTP 200"
  rl_ensure "$out"
  local cbv vid tok mode lmax lbase ttl t0 t1 rc rc2
  cbv=$(deploy_env APP_PSU_NIPOK_EXPECTED_CB); vid=$(deploy_env APP_PSU_NIPOK_VERIFIER_ID)
  tok=$(deploy_env APP_PSU_ONBOARDING_TOKEN)
  [ -n "$tok" ] || tok=$(. "$REPO/secrets/load-secrets.sh" >/dev/null 2>&1; printf '%s' "${ONBOARDING_TOKEN:-}")
  mode=$(deploy_env APP_PSU_ONBOARDING_MODE)
  lmax=$(deploy_env APP_PSU_LOCKOUT_MAX_ATTEMPTS); lbase=$(deploy_env APP_PSU_LOCKOUT_BASE_LOCK_SECONDS)
  ttl=$(deploy_env APP_PSU_NIPOK_CHALLENGE_TTL_SECONDS)
  [ -n "$cbv" ] || die "the auth-server has no APP_PSU_NIPOK_EXPECTED_CB"
  $KB -n "$GWN" get secret bank-cluster-certificate -o jsonpath='{.data.tls\.crt}' 2>/dev/null | base64 -d > "$out/gateway.pem"
  [ -s "$out/gateway.pem" ] || die "cannot read the gateway certificate (secret istio-system/bank-cluster-certificate)"
  echo "   verifier-id=${vid:-bank (default)} | onboarding ${mode:-enforce (Helm)} | lockout ${lmax:-5} attempts/${lbase:-60} s | nonce TTL ${ttl:-60} s | cb ${cbv:0:12}..."
  # Common variables for C7Probe (the onboarding token is not printed); C7_KB/C7_BNS: operator actions (psql in the postgres pod as
  # in run-all-psu.sh; deletion of the auth-server pod in the restart phase).
  local pe=(C7_BANK_URL="$BANK_URL" C7_GATEWAY_PEM="$out/gateway.pem" C7_EXPECTED_CB="$cbv" C7_VERIFIER_ID="${vid:-bank}"
            C7_ONBOARD_TOKEN="$tok" C7_ONBOARD_MODE="${mode:-enforce}" C7_LOCK_MAX="${lmax:-5}" C7_LOCK_BASE_S="${lbase:-60}"
            C7_NONCE_TTL_S="${ttl:-60}" C7_KB="$KB" C7_BNS="$BNS" C7_AS_LABEL="$AS_LABEL")
  t0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  say "[probe] (2) C7Probe: register, nipok, lockout, lifecycle, concurrency"
  env "${pe[@]}" C7_OUT="$out" C7_PHASES="register,nipok,lockout,lifecycle,concurrency" \
    "$jdk/bin/java" "$JVM_FLAGS" -Dstdout.encoding=UTF-8 -cp "$jar" "$C7_LT/C7Probe.java" 2>&1 | tee "$C7_DATA/logs/probe.console.log"
  rc=${PIPESTATUS[0]}
  say "[probe] (3) reasons on the auth-server side per probe PSU (log since $t0, before the pod is deleted)"
  $KB -n "$BNS" logs deploy/auth-server -c auth-server --since-time="$t0" 2>/dev/null \
    | grep -E 'NIPOK_AUTH|PSU_LOCKOUT|account_locked|G12_ONBOARDING' > "$out/authserver-probe.log"
  probe_reasons "$out/authserver-probe.log" "$out/probe-reasons.txt"
  say "[probe] (4) C7Probe: auth-server restart (pod deleted ${C7_RESTARTS:-3} times; in-memory nonce store)"
  mkdir -p "$out/restart"
  as_pods > "$out/restart/auth-server-pods-before.txt"
  t1=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  env "${pe[@]}" C7_OUT="$out/restart" C7_PHASES="restart" \
    "$jdk/bin/java" "$JVM_FLAGS" -Dstdout.encoding=UTF-8 -cp "$jar" "$C7_LT/C7Probe.java" 2>&1 | tee "$C7_DATA/logs/probe-restart.console.log"
  rc2=${PIPESTATUS[0]}
  as_pods > "$out/restart/auth-server-pods-after.txt"
  $KB -n "$BNS" logs deploy/auth-server -c auth-server --since-time="$t1" 2>/dev/null \
    | grep -E 'NIPOK_AUTH|PSU_LOCKOUT|account_locked' > "$out/restart/authserver-restart.log"
  probe_reasons "$out/restart/authserver-restart.log" "$out/restart/probe-reasons.txt"
  say "[probe] (5) auth-server after the restart"
  "$BANK/run-R1C6.sh" verify-as && ok "verify-as passed (new pod)" || warn "the auth-server fails verify-as after the restart"
  img_c6 || warn "the image after the restart differs from the C6 image"
  echo "   rate limiter (deployment): PSU=$(deploy_env APP_RATELIMIT_PSU_PER_SEC) PAR=$(deploy_env APP_RATELIMIT_PAR_PER_SEC)"
  [ "$rc" = 0 ] && ok "probe PASSED: every attempt as expected (e2e/probe/probe.json)" \
    || warn "probe has an unexpected attempt or a failed phase - see logs/probe.console.log"
  [ "$rc2" = 0 ] && ok "probe restart PASSED (e2e/probe/restart/probe.json)" \
    || warn "probe restart has an unexpected attempt or an error - see logs/probe-restart.console.log"
}

tls(){
  say "[tls] Envoy CPU per TLS handshake (bench-handshake-load.sh of the testbed: ECDSA P-256, Ed25519, RSA-3072)"
  e2e_preflight
  command -v jq >/dev/null || die "bench-handshake-load.sh needs jq: sudo apt-get install -y jq"
  [ -f "$SCRIPTS/bench-handshake-load.sh" ] || die "$SCRIPTS/bench-handshake-load.sh not found"
  local out="$C7_DATA/e2e/tls"; fresh_dir "$out"; manifest tls
  rl_ensure "$out"
  ( cd "$SCRIPTS" && bash ./bench-handshake-load.sh "${C7_TLS_DURATION:-8}" "${C7_TLS_WORKERS:-24}" ) 2>&1 \
    | tee "$out/handshake-load.txt"
  [ "${PIPESTATUS[0]}" = 0 ] && ok "done: $out/handshake-load.txt" || warn "bench-handshake-load.sh failed - see e2e/tls/handshake-load.txt"
}

report(){
  [ -d "$C7_DATA/e2e/hops" ] && python3 "$C7_LT/c7_hops.py" "$C7_DATA/e2e/hops"
  [ -d "$C7_DATA/e2e/burst" ] && python3 "$C7_LT/c7_burst.py" "$C7_DATA/e2e/burst"
  return 0
}

status(){
  say "[status] $C7_DATA"
  local j f m; j=$(saved_jar) && echo "   jar: ${j#$C7_DATA/} $(jar_ok && echo '(md5 matches)' || echo '(md5 does NOT match)')" || echo "   jar: (none)"
  for f in nipok-agent nipok-as envelope; do
    if [ -f "$C7_DATA/jmh/ablation/$f.json" ]; then
      printf '   jmh/ablation/%-16s %s records\n' "$f.json" "$(python3 -c "import json,sys;print(len(json.load(open(sys.argv[1]))))" "$C7_DATA/jmh/ablation/$f.json" 2>/dev/null)"
    else printf '   jmh/ablation/%-16s (none)\n' "$f.json"; fi
  done
  for m in ${M7//,/ }; do
    printf '   e2e/hops/%-22s %s summary.json (measured: %s)\n' "$m" "$(ls "$C7_DATA/e2e/hops/$m"/*.summary.json 2>/dev/null | wc -l)" \
      "$(ls "$C7_DATA/e2e/hops/$m"/*-rtt0-r*.summary.json 2>/dev/null | wc -l)"
  done
  printf '   e2e/burst                     %s summary.json, %s burst runs (c7.mode = burst)\n' \
    "$(ls "$C7_DATA/e2e/burst"/*-rtt0-r*.summary.json 2>/dev/null | wc -l)" "$(burst_runs "$C7_DATA/e2e/burst")"
  if [ -f "$C7_DATA/e2e/burst/burst.json" ]; then
    local nv ntot nbad; read -r nv ntot nbad <<< "$(burst_valid "$C7_DATA/e2e/burst")"
    echo "   e2e/burst valid runs: $nv/$ntot$([ "$nbad" = "-" ] || echo " (NOT valid: $nbad)")"
  fi
  [ -f "$C7_DATA/e2e/burst/transaction-resources.txt" ] && echo "   e2e/burst transaction: $(grep '^== ' "$C7_DATA/e2e/burst/transaction-resources.txt" | tail -1 | cut -c4-200)"
  [ -f "$C7_DATA/jmh/ablation/envelope-token-sunec.json" ] && printf '   jmh/ablation/%-16s %s records\n' "envelope-token-sunec.json" \
    "$(python3 -c "import json,sys;print(len(json.load(open(sys.argv[1]))))" "$C7_DATA/jmh/ablation/envelope-token-sunec.json" 2>/dev/null)"
  [ -f "$C7_DATA/e2e/probe/probe.json" ] && echo "   e2e/probe: $(grep -o '"status": "[^"]*"' "$C7_DATA/e2e/probe/probe.json")" || echo "   e2e/probe: (none)"
  [ -f "$C7_DATA/e2e/probe/restart/probe.json" ] && echo "   e2e/probe/restart: $(grep -o '"status": "[^"]*"' "$C7_DATA/e2e/probe/restart/probe.json")" \
    || echo "   e2e/probe/restart: (none)"
  [ -f "$C7_DATA/e2e/tls/handshake-load.txt" ] && echo "   e2e/tls: handshake-load.txt present" || echo "   e2e/tls: (none)"
  runner_ok && echo "   runner: ${C7_RUNNER#$REPO/} -> $RUNNER_LINK" || echo "   runner: link ${C7_RUNNER#$REPO/} MISSING or WRONG"
  [ -f "$C7_DATA/e2e/hops/gateway-accesslog.txt" ] && echo "   e2e/hops access log: $(grep -c '^== ' "$C7_DATA/e2e/hops/gateway-accesslog.txt") entries (gateway-accesslog.txt)"
  for f in hops burst probe tls; do   # the exit code of the last check must not become the exit code of the status command
    if [ -f "$C7_DATA/e2e/$f/rate-limiter.txt" ]; then
      printf '   e2e/%-5s rate limiter: %s\n' "$f" "$(tail -n 1 "$C7_DATA/e2e/$f/rate-limiter.txt" | sed 's/.*| used: //')"
    fi
  done
}
diag(){ # read only: access log of the gateway, access-token signing provider of the auth-server; writes logs/diag-<time>.txt
  say "[diag] read only: access log of istio-ingressgateway, Ed25519 signing strategy of the auth-server"
  clusters_up || die "clusters are not running (start them: cd $REPO && ./up.sh)"
  mkdir -p "$C7_DATA/logs"; local f lg hide='pass|secret|pwd|token'; f="$C7_DATA/logs/diag-$(date +%Y%m%d-%H%M%S).txt"
  {
    echo "== $(date -Iseconds) | run-R1C7.sh $(md5sum "$BANK/run-R1C7.sh" | cut -c1-32)"
    echo "== access log of $GWD"
    gw_mesh_accesslog
    if gw_accesslog_probe; then echo "the gateway currently WRITES an access log (the marked request is in the log)"
    else echo "the gateway currently writes NO access log (the marked request is not in the log after ${C7_GW_PROBE_TRIES:-6} attempts, ${C7_GW_PROBE_WAIT:-5} s each)"; fi
    echo "== auth-server: Ed25519 signing strategy (log of the current pod, lines with pass/secret/pwd/token not printed) and env APP_ED25519_PROVIDER"
    lg=$($KB -n "$BNS" logs deploy/auth-server -c auth-server 2>/dev/null | grep -i -E 'Ed25519 signing strategy|Ed25519 strategy|falling back|conscrypt')
    printf '%s\n' "$lg" | grep -v -i -E "$hide" | grep -E 'Ed25519' | head -6
    printf '%s\n' "$lg" | grep -v -i -E "$hide" | grep -v -E 'Ed25519' | grep . | head -4
    echo "(the log matches $(printf '%s\n' "$lg" | grep -c .) lines: at most 6 Ed25519 lines + 4 other lines printed; $(printf '%s\n' "$lg" | grep -c -i -E "$hide") lines with pass/secret/pwd/token not printed)"
    echo "APP_ED25519_PROVIDER=$(deploy_env APP_ED25519_PROVIDER)   (empty = not set; code default: conscrypt-boringssl)"
    echo "pod auth-server: $(as_pods | head -1)"
    img_c6 || true
  } 2>&1 | tee "$f"
  ok "written: ${f#$REPO/}"
}
pm_cut(){ # stdin -> the first $1 and the last $2 lines; more lines: the number left out in the middle is printed
  awk -v H="$1" -v T="$2" '{ a[NR] = $0 }
    END { if (NR <= H + T) { for (i = 1; i <= NR; i++) print a[i] }
          else { for (i = 1; i <= H; i++) print a[i]; printf "... (%d lines left out)\n", NR - H - T; for (i = NR - T + 1; i <= NR; i++) print a[i] } }'
}
postmortem(){ # read only: why the burst step failed after transaction was OOM-killed. Pod state, logs of transaction
  # (including the run before the kill) and customer-aggregator, events, node; memory of transaction and request outcomes per
  # burst run from the Prometheus of the bank. Writes logs/postmortem-<time>.txt. Run it BEFORE restarting the testbed (a restart
  # loses the logs of the old container and the Prometheus data).
  say "[postmortem] read only: transaction, customer-aggregator, Prometheus (windows of the runs in e2e/burst)"
  clusters_up || die "clusters are not running - nothing left to read (logs and Prometheus data are lost when the clusters stop)"
  mkdir -p "$C7_DATA/logs"
  local f hide='pass|secret|pwd|token|authoriz|bearer|eyJ|credential|private' t0 since=(--since=8h) sw="last 8 hours"
  f="$C7_DATA/logs/postmortem-$(date +%Y%m%d-%H%M%S).txt"
  # log window: from 10 minutes before the first burst run (.cgx0 mark), independent of when the command runs; no mark: last 8 hours
  t0=$(python3 -c 'import glob, os, sys
m = [os.path.getmtime(x) for x in glob.glob(os.path.join(sys.argv[1], ".*.cgx0"))]
print(int(min(m)) - 600 if m else "")' "$C7_DATA/e2e/burst" 2>/dev/null)
  if [ -n "$t0" ]; then
    since=(--since-time="$(date -u -d "@$t0" +%Y-%m-%dT%H:%M:%SZ)"); sw="since $(date -d "@$t0" '+%Y-%m-%d %H:%M:%S') (10 minutes before the first burst run)"
  fi
  {
    echo "== $(date -Iseconds) | run-R1C7.sh $(md5sum "$BANK/run-R1C7.sh" | cut -c1-32)"
    echo "== pods in $BNS"
    $KB -n "$BNS" get pods 2>&1 | sed 's/^/   /'
    echo "== transaction: current pods"
    tx_pods | sed 's/^/   /'
    echo "== transaction: resources in the deployment, JAVA_TOOL_OPTIONS, names of the env variables (values not printed)"
    $KB -n "$BNS" get deploy/"$TX_DEP" -o json 2>/dev/null | python3 -c '
import json, sys
try:
    cs = json.load(sys.stdin)["spec"]["template"]["spec"]["containers"]
except Exception:
    print("   (cannot be read)"); sys.exit(0)
for c in cs:
    env = c.get("env") or []
    jto = next((e.get("value", "") for e in env if e.get("name") == "JAVA_TOOL_OPTIONS"), "")
    print("   container %s: resources=%s JAVA_TOOL_OPTIONS=%s" % (c.get("name"), json.dumps(c.get("resources") or {}, sort_keys=True), jto or "<none>"))
    print("   env: %s" % ", ".join(e.get("name", "?") for e in env))'
    echo "== ready endpoints of the services transaction and customer-aggregator"
    for s in "$TX_DEP" customer-aggregator; do
      echo "   $s: $($KB -n "$BNS" get endpoints "$s" -o jsonpath='{range .subsets[*]}{range .addresses[*]}{.ip}{" "}{end}{"| not ready: "}{range .notReadyAddresses[*]}{.ip}{" "}{end}{end}' 2>&1)"
    done
    echo "== related events in $BNS (OOM, kill, restart, failed probe), last 40 lines"
    $KB -n "$BNS" get events --sort-by=.lastTimestamp --no-headers \
      -o custom-columns='T:.lastTimestamp,TYPE:.type,REASON:.reason,OBJ:.involvedObject.name,MSG:.message' 2>&1 \
      | grep -i -E "transaction|aggregator|oom|kill|backoff|unhealthy|fail|evict|restart" | grep -v -i -E "$hide" | tail -40 | sed 's/^/   /'
    echo "== node bank-cluster-profile: conditions, allocated resources"
    $KB describe node bank-cluster-profile 2>&1 | sed -n '/^Conditions:/,/^Addresses:/p;/^Allocated resources:/,/^Events:/p' \
      | grep -v -i -E "$hide" | sed 's/^/   /'
    echo "== transaction log of the run BEFORE the kill (last 120 lines; lines with $hide left out)"
    $KB -n "$BNS" logs deploy/"$TX_DEP" -c "$TX_C" --previous --tail=120 2>&1 | grep -v -i -E "$hide" | cut -c1-300 | sed 's/^/   /'
    echo "== current transaction log, $sw: start-up, WARN, ERROR, exceptions (first 60 lines, last 20 lines)"
    $KB -n "$BNS" logs deploy/"$TX_DEP" -c "$TX_C" "${since[@]}" 2>&1 \
      | grep -i -E "started|picked up|warn|error|exception|timeout|hikari|refused|reset" | grep -v -i -E "$hide" | cut -c1-300 \
      | pm_cut 60 20 | sed 's/^/   /'
    echo "== customer-aggregator log, $sw: WARN, ERROR, exceptions, timeouts (first 60 lines, last 20 lines)"
    $KB -n "$BNS" logs deploy/customer-aggregator -c customer-aggregator "${since[@]}" 2>&1 \
      | grep -i -E "warn|error|exception|timeout|refused|reset|503|504" | grep -v -i -E "$hide" | cut -c1-300 \
      | pm_cut 60 20 | sed 's/^/   /'
    echo "== Prometheus of the bank: memory of transaction and request outcomes per run in e2e/burst"
    python3 - "$C7_DATA/e2e/burst" "${PROM_BANK:-https://prometheus.bank.openbanking.dev:30443}" <<'PY'
import glob, json, os, re, ssl, sys, urllib.parse, urllib.request
from datetime import datetime
d, base = sys.argv[1], sys.argv[2].rstrip("/")
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE   # as in istio_hops.py
op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
def hm(t): return datetime.fromtimestamp(t).strftime("%H:%M:%S")
def get(path, params):
    with op.open(base + path + "?" + urllib.parse.urlencode(params), timeout=30) as r:
        j = json.loads(r.read().decode("utf-8"))
    if j.get("status") != "success":
        raise RuntimeError(j.get("error"))
    return j["data"]
def q(expr, t):
    try:
        return [(s.get("metric", {}), float(s["value"][1])) for s in get("/api/v1/query", {"query": expr, "time": "%.3f" % t})["result"]]
    except Exception as e:
        print("   ! query failed (%s): %s" % (e, expr[:110])); return []
def outcomes(rows):
    rows = [(m, v) for m, v in rows if v >= 0.5]
    return ", ".join("%s%s×%d" % (m.get("response_code", "?"), "" if m.get("response_flags") in (None, "", "-") else " " + m["response_flags"], round(v))
                     for m, v in sorted(rows, key=lambda x: -x[1])) or "-"
runs = []
for fn in glob.glob(os.path.join(d, "*.summary.json")):
    tag = os.path.basename(fn)[: -len(".summary.json")]
    c0, c1 = os.path.join(d, "." + tag + ".cgx0"), os.path.join(d, "." + tag + ".cgx1")
    if os.path.isfile(c0) and os.path.isfile(c1) and os.path.getmtime(c1) - os.path.getmtime(c0) >= 5:
        runs.append((os.path.getmtime(c0), os.path.getmtime(c1), tag))
runs.sort()
if not runs:
    print("   (no run with .cgx0/.cgx1 marks in %s)" % d); sys.exit(0)
print("   %d runs in %s, %s -> %s (host time)" % (len(runs), d, hm(runs[0][0]), hm(runs[-1][1])))
try:
    st = get("/api/v1/status/runtimeinfo", {}).get("startTime", "?")
except Exception as e:
    print("   ! cannot reach Prometheus %s: %s" % (base, e)); sys.exit(0)
print("   Prometheus %s started at %s (UTC; when later than the first run, earlier data are lost)" % (base, st))
M = 'namespace="bank-cluster-nsp",container="transaction"'
for t0, t1, tag in runs:
    w = max(5, int(t1 - t0))
    mem = [v for _, v in q("max_over_time(container_memory_working_set_bytes{%s}[%ds])" % (M, w), t1)]
    lim = [v for _, v in q("container_spec_memory_limit_bytes{%s}" % M, t1)]
    oomr = q("increase(container_oom_events_total{%s}[%ds])" % (M, w), t1)
    oom = "%.0f" % sum(v for _, v in oomr) if oomr else "-"   # no series: "-", never 0
    ag = q('sum by (response_code,response_flags) (increase(istio_requests_total{reporter="source",source_workload="customer-aggregator",destination_workload="transaction"}[%ds]))' % w, t1)
    gw = q('sum by (response_code,response_flags) (increase(istio_requests_total{reporter="source",source_workload="istio-ingressgateway",destination_workload="customer-aggregator"}[%ds]))' % w, t1)
    print("   %-33s %s-%s | transaction: max memory %s MiB (limit %s MiB), OOM %s | aggregator->transaction: %s | gateway->aggregator: %s" % (
        tag, hm(t0), hm(t1), "%.0f" % (max(mem) / 2**20) if mem else "-", "%.0f" % (max(lim) / 2**20) if lim else "-",
        oom, outcomes(ag), outcomes(gw)))
t0, t1 = runs[0][0] - 3600, runs[-1][1] + 60
try:
    rr = get("/api/v1/query_range", {"query": "max by (pod) (container_memory_working_set_bytes{%s})" % M, "start": "%.0f" % t0, "end": "%.0f" % t1, "step": "60"})["result"]
except Exception as e:
    rr = []; print("   ! query_range failed: %s" % e)
for s in rr:
    pts = ["%s %.0f" % (datetime.fromtimestamp(float(t)).strftime("%H:%M"), float(v) / 2**20) for t, v in s.get("values", [])]
    print("   memory (MiB, per minute) of pod %s:" % s.get("metric", {}).get("pod", "?"))
    for i in range(0, len(pts), 10):
        print("      " + " | ".join(pts[i:i + 10]))
for m, v in q("container_start_time_seconds{%s}" % M, runs[-1][1]):
    print("   transaction container (id %s...) started at %s" % (str(m.get("id", ""))[-12:], datetime.fromtimestamp(v).strftime("%Y-%m-%d %H:%M:%S")))
PY
  } 2>&1 | tee "$f"
  ok "written: ${f#$REPO/}"
}
tx_mem_restore_cmd(){ # restore the resources of transaction by hand (after the burst step was killed)
  say "[tx-mem-restore] restore the original resources of $BNS/$TX_DEP from e2e/burst/transaction-resources.orig.json"
  clusters_up || die "clusters are not running"
  [ -s "$C7_DATA/e2e/burst/transaction-resources.orig.json" ] || die "no e2e/burst/transaction-resources.orig.json (the burst step changed nothing)"
  tx_mem_restore "$C7_DATA/e2e/burst" "by hand" || die "not restored"
}
jmh_sunec(){ # JMH as_token_sign, as_token_encode with the SunEC token-signing provider (testbed: APP_ED25519_PROVIDER=jca-sunec)
  say "[jmh-sunec] JMH of access-token signing with SunEC -> $C7_DATA/jmh/ablation/envelope-token-sunec.json"
  [ -z "$(c6_running)" ] || die "a C6 measurement is running - wait until it ends before measuring"
  jar_ok || die "no valid jar (./run-R1C7.sh build)"
  [ -x "$TEMURIN_JRE/bin/java" ] || die "$TEMURIN_JRE not found - run: ./run-R1C6.sh setup-jvm"
  [ "$(awk '/SwapTotal/{print $2}' /proc/meminfo)" = 0 ] || die "swap is on - run: sudo swapoff -a"
  local out="$C7_DATA/jmh/ablation" jar res log="$C7_DATA/logs/jmh-envelope-sunec.console.log"; jar=$(saved_jar)
  res="$out/envelope-token-sunec.json"
  [ -s "$out/envelope.json" ] || die "jmh/ablation/envelope.json not found (run ./run-R1C7.sh jmh first)"
  if [ -e "$res" ]; then
    [ "${FORCE:-0}" = 1 ] || die "${res#$REPO/} already exists - to measure again: FORCE=1 ./run-R1C7.sh jmh-sunec"
    local sfx; sfx=".bak-$(date +%Y%m%d-%H%M%S)"
    mv "$res" "$res$sfx"; [ -f "$out/env-token-sunec.txt" ] && mv "$out/env-token-sunec.txt" "$out/env-token-sunec.txt$sfx"
    [ -f "$log" ] && mv "$log" "$log$sfx"; warn "old copy renamed (*$sfx)"
  fi
  [ "$J_ISOLATE" = 1 ] && stop_clusters
  manifest jmh-sunec
  local common=(-f "$J_FORKS" -wi "$J_WI" -w 1s -i "$J_IT" -r 1s -tu us -bm avgt -prof gc)
  { echo "start: $(date -Iseconds)"; echo "jar: $jar md5 $(md5sum "$jar" | cut -c1-32)"
    echo "jvm: $("$TEMURIN_JRE/bin/java" -version 2>&1 | grep -m1 Runtime)"; echo "taskset: $J_CPUS"
    echo "jmh: ${common[*]}"; echo "benchmark: EnvelopeAblationBenchmark.as_token_(sign|encode), tokenProvider=SunEC"
    echo "clusters_stopped: $J_ISOLATE"; } > "$out/env-token-sunec.txt"
  run_logged jmh-envelope-sunec taskset -c "$J_CPUS" "$TEMURIN_JRE/bin/java" "$JVM_FLAGS" -jar "$jar" \
    'bench\.c7\.EnvelopeAblationBenchmark\.as_token_(sign|encode)$' -p tokenProvider=SunEC "${common[@]}" \
    -rf json -rff "$res" || die "SunEC JMH failed (logs/jmh-envelope-sunec.console.log)"
  echo "end: $(date -Iseconds)" >> "$out/env-token-sunec.txt"
  grep -q 'token signing provider SunEC' "$log" || warn "the correctness-gate line 'token signing provider SunEC' is missing from the log"
  ok "done: ${res#$REPO/} ($(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$res" 2>/dev/null) records)"
  warn "JMH done - start the clusters again if needed: cd $REPO && ./up.sh"
}
export_data(){
  [ -n "$EXPORT_DIR" ] || die "set EXPORT_DIR=<target directory> (for example a directory on another disk)"
  say "[export] $C7_DATA -> $EXPORT_DIR"
  [ -d "$(dirname "$EXPORT_DIR")" ] || die "$(dirname "$EXPORT_DIR") not found"
  mkdir -p "$EXPORT_DIR" && cp -r --preserve=timestamps "$C7_DATA/." "$EXPORT_DIR/" \
    && ok "copied ($(du -sh "$EXPORT_DIR" 2>/dev/null | cut -f1))" || die "copy failed"
}

cmd="${1:-}"; shift || true
case "$cmd" in
  check)     check ;;
  build)     build ;;
  smoke)     smoke ;;
  jmh)       jmh ;;
  hops)      hops ;;
  burst)     burst ;;
  probe)     probe ;;
  tls)       tls ;;
  report)    report ;;
  status)    status ;;
  diag)      diag ;;
  postmortem) postmortem ;;
  tx-mem-restore) tx_mem_restore_cmd ;;
  jmh-sunec) jmh_sunec ;;
  export)     export_data ;;
  *) awk 'NR>1 {print} NR>1 && /^# ====/ && ++c==2 {exit}' "$0"; exit 1 ;;
esac
