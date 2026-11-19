#!/usr/bin/env bash
# ============================================================================
# run-R1C6.sh - single control point of the JMH and load-test campaign of the statistical evaluation (Reviewer 1, Comment 6)
#
# The campaign is written to $C6_DATA (default testbed/bank/benchmark-R1-C6):
#   jmh/main                    JMH of the seven mechanisms      (eval_jmh_final_manuscript_nipok.sh, OUTDIR)
#   jmh/main/submission         JMH figures in the layout of the paper (SUBMISSION=1), redrawn from official-final.json
#   jmh/fbc-ab                  A/B of NIPoK verification, Straus against fixed-base comb (eval_verify_nipok_fbc_normal.sh, RES)
#   jmh/argon2id-sensitivity    Argon2id sensitivity            (eval_jmh_argon2_sensitivity.sh, OUTDIR)
#   jmh/jvm-control             GraalVM against Temurin control (eval_jmh_jvm_control.sh, OUT)
#   jmh/params                  JMH parameters of every step (read from the result JSON files) + README.txt
#   loadtest/block1 ... block6  six load-test blocks, Williams order (mtls last)
#   loadtest/wan                wide-area phase (RTT 0/20/50/100 ms, seven mechanisms)
#   loadtest/params             load-test parameters of every step (variables passed in + meta.txt) + README.txt
#   logs/                       console log of every step and copies of the raw JMH logs;  MANIFEST.txt  trace of every step
#
# Usage (from testbed/bank, on the measurement host):
#   ./run-R1C6.sh check            # files, JVM, clusters, measurement conditions
#   ./run-R1C6.sh setup-jvm        # once: JRE Temurin 24+36 from the image eclipse-temurin:24_36-jre-noble
#   ./run-R1C6.sh redeploy-as      # rebuild the auth-server image + rollout + check
#   ./run-R1C6.sh verify-as        # check that the running auth-server has the expected authorization store and PAR guard
#   ./run-R1C6.sh jmh-main         # ~65 min (stops the clusters); also redraws the JMH figures into jmh/main/submission
#   ./run-R1C6.sh jmh-fbc          # ~20 min (stops the clusters)
#   ./run-R1C6.sh jmh-argon2       # ~45 min (stops the clusters)
#   ./run-R1C6.sh jvm-control      # ~15 min (stops the clusters; needs GraalVM CE 24, see GRAAL_JAVA in eval_jmh_jvm_control.sh)
#   ./run-R1C6.sh jmh-all          # the four steps above in sequence (~2.5 h)
#   ./run-R1C6.sh jmh-figs         # only redraw the JMH figures from jmh/main/official-final.json (no measurement)
#   ./run-R1C6.sh pilot [A|B|C]    # pilot runs, not used for the paper (clusters running)
#   ./run-R1C6.sh block N          # block N = 1..6 (about 3.2 h per block; eight mechanisms; clusters running)
#   ./run-R1C6.sh wan              # wide-area phase, seven mechanisms (~2.8 h)
#   ./run-R1C6.sh params           # rewrite jmh/params and loadtest/params from existing results
#   ./run-R1C6.sh status           # show what exists
#   ./run-R1C6.sh export           # copy $C6_DATA to $EXPORT_DIR (for example a disk outside the measurement host)
#   ./run-R1C6.sh fix-node-mem     # once: raise the docker memory limit of the customer node to NODE_MEM_MIN_MIB (live change)
#   ./run-R1C6.sh stress-agent     # agent check: password_owasp + nipok straight at 128 journeys/s (768 VUs), ~10 min;
#                                  #   STRESS_MECHS=<list> selects the mechanisms (password is not accepted); rerun: FORCE=1 ...
# FORCE=1 renames an existing result (and its params/log files) to *.bak-<time> before measuring again.
# JMH_JAR=saved runs the JMH steps on the jar saved in jmh/params (its md5 must match jmh/params/jmh-jar.md5 or JMH_JAR_MD5):
#   no SPI publication, no build, no Gradle call (only --stop of the daemon).
# The auth-server must log "Authorization store" and "PAR_REQUEST_URI_GUARD active" at start-up (verify-as is run before every
#   block and restarts the auth-server once when its log has rotated).
# Do not use the measurement host for other work (terminal, IDE) while a step runs.
# ============================================================================
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"   # testbed root (holds bank/, customer/, tpp/, up.sh)
BANK="$REPO/bank"
JMH_DIR="${JMH_DIR:-$BANK/benchmark/crypto-jmh}"
LT_DIR="${LT_DIR:-$BANK/kubernetes/loadtest/k6-psu-auth}"
C6_DATA="${C6_DATA:-$BANK/benchmark-R1-C6}"   # campaign directory; pilot runs use $BANK/R1-C6-data
EXPORT_DIR="${EXPORT_DIR:-}"                    # target of the export command (no default)
TEMURIN_IMAGE="${TEMURIN_IMAGE:-eclipse-temurin:24_36-jre-noble}"   # same image as the auth-server
TEMURIN_JRE="${TEMURIN_JRE:-$HOME/jdks/temurin-24_36-jre}"

# JMH (Temurin 24, 10 forks)
J_FORKS="${J_FORKS:-10}"; J_WI="${J_WI:-8}"; J_IT="${J_IT:-10}"; J_CPUS="${J_CPUS:-0-7}"; J_ISOLATE="${J_ISOLATE:-1}"
# jar of the JMH steps: empty = eval_*.sh builds it; "saved" = the jar saved in jmh/params; or a path to a jar
JMH_JAR="${JMH_JAR:-}"; JMH_JAR_MD5="${JMH_JAR_MD5:-}"; JJ=""; JJ_MD5=""; _JJ_DONE=0; _README_ROT=0

# Load test (parameters of the campaign)
LT_COMMON=(REPEATS=3 VUS=16 DURATION=60s WARMUP_RATE=16
           KNEE_RATES=4,8,16,32,64,128,256 KNEE_DUR=30s KNEE_CONFIRM=1 KNEE_REFINE=4 KNEE_COOLDOWN=10
           SWEEP=1 SWEEP_FRACS=0.3,0.6,1.0 SWEEP_REPEATS=2 TARGET_UTIL=0.6 RTT_SWEEP=0
           CG_CPU=1 CGX_CPU=1 RL_COUNT=1 LOG_ERRORS=1
           AGENT_CPU=4 AGENT_CPU_REQ=2 AGENT_MEM=2Gi
           SETTLE=1 SETTLE_CPU=0.5 SETTLE_INT=3 SETTLE_MAX=600 SETTLE_PROBE_MS=5000
           NOISE_RETRY=2 NOISE_CORES=2.5 NOISE_WAIT=60)
# SETTLE_*: run-all-psu.sh waits until the auth-server has recovered before the next run
# AGENT_MEM=2Gi: memory of the customer-agent pod (requests = limits; heap stays AGENT_HEAP=512m of run-all-psu.sh);
#   1Gi was OOM-killed at 768 VUs. The customer node needs >= NODE_MEM_MIN_MIB (fix-node-mem).
# NOISE_*: a run with host_other_cores > 2.5 (host busy outside the three clusters and k6) is kept (*.noisy<n>) and
#   repeated after 60 s + settle, at most twice.
NODE_MEM_MIN_MIB="${NODE_MEM_MIN_MIB:-4096}"; CUST_NODE="${CUST_NODE:-customer-cluster-profile}"
# agent: CPU limit 4 (2 was a bottleneck), request 2, so the CPU reserved on the customer node is unchanged
#   (two agent pods can run together during a rollout). Knee step 256: the knee can exceed 128 journeys/s.
RL_UP=(RL_PSU=100000 RL_PAR=100000)
# parameters of the wide-area phase (wan command and loadtest/params/README.txt)
WAN_ARGS=(RUN_LABEL=wan L8_ONLY=1 RTT_MECHS=nipok,schnorr_interactive,ed25519,password,private_key_jwt,ml_dsa,mtls
          RTT_LIST=0,20,50,100 RTT_REPEATS=3 L8_FIXED_RATE=8)
# Williams Latin square 6x6 (seed 20261111): balanced positions and predecessors; mtls always last.
# password_owasp right after password in every block; the order of the other seven mechanisms follows the square.
ORD=( ""
  "private_key_jwt,password,password_owasp,nipok,ml_dsa,schnorr_interactive,ed25519,mtls"
  "schnorr_interactive,nipok,ed25519,private_key_jwt,ml_dsa,password,password_owasp,mtls"
  "ml_dsa,ed25519,password,password_owasp,schnorr_interactive,private_key_jwt,nipok,mtls"
  "nipok,private_key_jwt,schnorr_interactive,password,password_owasp,ed25519,ml_dsa,mtls"
  "ed25519,schnorr_interactive,ml_dsa,nipok,password,password_owasp,private_key_jwt,mtls"
  "password,password_owasp,ml_dsa,private_key_jwt,ed25519,nipok,schnorr_interactive,mtls" )

say(){ printf '\n== %s\n' "$*"; }
ok(){  printf '   [ok] %s\n' "$*"; }
warn(){ printf '   [warn] %s\n' "$*"; }
die(){ printf '\nERROR: %s\n' "$*" >&2; exit 1; }

mkdir -p "$C6_DATA/jmh/params" "$C6_DATA/loadtest/params" "$C6_DATA/logs"
MANIFEST="$C6_DATA/MANIFEST.txt"

FILES=( "$LT_DIR/run-all-psu.sh"
        "$JMH_DIR/eval_jmh_final_manuscript_nipok.sh"
        "$JMH_DIR/eval_verify_nipok_fbc_normal.sh"
        "$JMH_DIR/eval_jmh_argon2_sensitivity.sh"
        "$JMH_DIR/src/jmh/java/bench/Argon2SensitivityBenchmark.java"
        "$JMH_DIR/src/jmh/java/bench/Argon2Benchmark.java"
        "$JMH_DIR/eval_jmh_jvm_control.sh"
        "$JMH_DIR/eval_manuscript.py"
        "$JMH_DIR/plot_fbc_ab.py"
        "$JMH_DIR/build.gradle"
        "$LT_DIR/bench-psu-auth.js"
        "$LT_DIR/plot_loadtest.py"
        "$LT_DIR/R1C6PhcTool.java"
        "$BANK/run-R1C6.sh"
        "$BANK/spring-cloud/authorization-server/src/main/java/sample/config/AuthorizationServerConfig.java"
        "$BANK/spring-cloud/authorization-server/src/main/java/sample/config/IndexedInMemoryAuthorizationService.java"
        "$BANK/spring-cloud/authorization-server/src/main/java/sample/config/ParRequestUriGuard.java"
        "$BANK/psu-auth-spi/src/main/java/com/openbanking/psu/auth/spi/crypto/nipok/NipokEncoding.java"
        "$BANK/psu-auth-spi/src/main/java/com/openbanking/psu/auth/spi/crypto/nipok/NipokVerifier.java"
        "$BANK/psu-auth-spi/src/main/java/com/openbanking/psu/auth/spi/wallet/SimulatorWalletProvider.java"
        "$BANK/spring-cloud/authorization-server/src/main/java/sample/psu/nipok/NipokAuthenticationProvider.java"
        "$BANK/spring-cloud/authorization-server/src/main/java/sample/psu/web/PsuRegistrationController.java" )

manifest(){ # $1 = step
  { echo "== $(date -Iseconds) | step: $1 | host: $(hostname) | kernel: $(uname -r) | nproc: $(nproc)"
    echo "   git: $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo n/a) (dirty files: $(git -C "$REPO" status --porcelain 2>/dev/null | wc -l))"
    local f; for f in "${FILES[@]}"; do [ -f "$f" ] && echo "   md5 $(md5sum "$f" | cut -c1-32)  ${f#$REPO/}"; done
    echo "   java on PATH: $(command -v java) | $(java -version 2>&1 | grep -m1 -E 'Runtime Environment' || echo n/a)"
    echo "   docker: $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo n/a) | minikube: $(minikube version --short 2>/dev/null || echo n/a) | k6: $(k6 version 2>/dev/null | head -1)"
    # docker limits of the three minikube nodes (NanoCpus=0: no CPU limit; Memory in bytes)
    echo "   minikube nodes: $(docker inspect -f '{{.Name}} NanoCpus={{.HostConfig.NanoCpus}} CpuQuota={{.HostConfig.CpuQuota}} Memory={{.HostConfig.Memory}}' \
      bank-cluster-profile customer-cluster-profile tpp-cluster-profile 2>/dev/null | tr '\n' ';' || echo n/a)"
    # capacity/allocatable reported by the kubelet (used by the scheduler) + reservations on the customer node; empty when stopped
    echo "   k8s nodes: $(k8s_nodes)"
    echo "   customer node allocated: $(cust_allocated)"
    # measurement conditions: power source, power plan, clocksource, Windows time between two monotonic WSL timestamps
    echo "   clocksource: $(cat /sys/devices/system/clocksource/clocksource0/current_clocksource 2>/dev/null || echo n/a)"
    echo "   windows: $(win_info)"
    # jar of the JMH step
    case "$1" in jmh-*|jvm-control) if [ -n "$JJ" ]; then echo "   jmh jar: $JJ md5 $JJ_MD5 (saved jar, no build)"
      else echo "   jmh jar: rebuilt by eval_*.sh (JMH_JAR empty)"; fi ;; esac
  } >> "$MANIFEST"
}
# find Windows programs: PATH of WSL (appendWindowsPath) or the standard location under /mnt/c
winexe(){
  local p; p=$(command -v "$1" 2>/dev/null) && { echo "$p"; return 0; }
  for p in "/mnt/c/Windows/System32/$1" "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/$1"; do
    [ -x "$p" ] && { echo "$p"; return 0; }
  done
  return 1
}
# "BatteryStatus=... Charge=...% PowerOnline=... win_utc_ms=... | wsl_mono=<before>..<after> wsl_real=... | plan: ..."
#   BatteryStatus (Win32_Battery): 1 = on battery, 2 = on mains; PowerOnline (root/wmi BatteryStatus): True = charger connected.
#   win_utc_ms is taken between the two wsl_mono values, so two steps hours apart check the clock rate of the VM.
win_info(){
  local ps pc m0 m1 r w p
  ps=$(winexe powershell.exe) || { echo "n/a (powershell.exe cannot be called from WSL)"; return 0; }
  m0=$(python3 -c 'import time;print("%.6f"%time.monotonic())'); r=$(date +%s.%N)
  w=$(timeout 40 "$ps" -NoProfile -NonInteractive -Command '$b=Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1; $o=(Get-CimInstance -Namespace root/wmi -ClassName BatteryStatus -ErrorAction SilentlyContinue | Select-Object -First 1).PowerOnline; "BatteryStatus=" + $b.BatteryStatus + " Charge=" + $b.EstimatedChargeRemaining + "% PowerOnline=" + $o + " win_utc_ms=" + [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()' 2>/dev/null | tr -d '\r' | grep -m1 'win_utc_ms=')
  m1=$(python3 -c 'import time;print("%.6f"%time.monotonic())')
  pc=$(winexe powercfg.exe) && p=$(timeout 20 "$pc" /getactivescheme 2>/dev/null | tr -d '\r' | grep -m1 -i 'GUID' | sed 's/^[^:]*: *//')
  echo "${w:-n/a} | wsl_mono=${m0}..${m1} wsl_real=${r} | plan: ${p:-n/a}"
}
# "<node> capacity.cpu=... allocatable.cpu=... allocatable.memory=...;" for the three clusters
k8s_nodes(){ local c; for c in bank-cluster-profile customer-cluster-profile tpp-cluster-profile; do
  kubectl --context "$c" get nodes --request-timeout=10s -o jsonpath='{range .items[*]}{.metadata.name} capacity.cpu={.status.capacity.cpu} allocatable.cpu={.status.allocatable.cpu} allocatable.memory={.status.allocatable.memory}{";"}{end}' 2>/dev/null
  done; }
# total CPU and RAM requests/limits reserved on the customer node ("Allocated resources" of kubectl describe node)
cust_allocated(){ kubectl --context customer-cluster-profile describe node customer-cluster-profile --request-timeout=10s 2>/dev/null \
  | sed -n '/^Allocated resources:/,/^Events:/p' | grep -E '^[[:space:]]+(cpu|memory)[[:space:]]' | tr -s ' ' | tr '\n' ';'; }

# --- JVM for JMH: Temurin 24+36 (as in the auth-server image); JAVA_HOME keeps the JDK used by Gradle ---
find_build_jdk(){
  local j
  if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/javac" ]; then echo "$JAVA_HOME"; return 0; fi
  j=$(command -v javac 2>/dev/null) && { dirname "$(dirname "$(readlink -f "$j")")"; return 0; }
  for j in "$HOME"/.sdkman/candidates/java/current /usr/lib/jvm/*; do [ -x "$j/bin/javac" ] && { echo "$j"; return 0; }; done
  return 1
}
use_temurin(){
  [ -x "$TEMURIN_JRE/bin/java" ] || die "$TEMURIN_JRE not found - run first: ./run-R1C6.sh setup-jvm"
  local bj; bj=$(find_build_jdk) || die "no JDK with javac found for Gradle - set JAVA_HOME to the JDK 24 used for builds"
  export JAVA_HOME="$bj"
  export PATH="$TEMURIN_JRE/bin:$PATH"
  java -version 2>&1 | grep -q 'Temurin' && java -version 2>&1 | grep -qE 'version "24' \
    || die "java on PATH is not Temurin 24: $(java -version 2>&1 | tr '\n' ' ')"
  ok "measurement JVM: $(java -version 2>&1 | grep -m1 Runtime) | build JDK (JAVA_HOME): $JAVA_HOME"
}
# --- PHC tool of password_owasp: a JDK >= 24 with javac (source-file mode needs jdk.compiler; the Temurin JRE lacks it)
jdk_major(){ "$1/bin/java" -version 2>&1 | sed -n '1s/.*version "\([0-9][0-9]*\).*/\1/p'; }
find_phc_jdk(){
  local c m
  if [ -n "${PHC_JDK:-}" ]; then echo "$PHC_JDK"; return 0; fi
  for c in "$(find_build_jdk 2>/dev/null)" "$HOME"/.sdkman/candidates/java/* /usr/lib/jvm/* "$HOME"/jdks/*; do
    [ -n "$c" ] && [ -x "$c/bin/java" ] && [ -x "$c/bin/javac" ] || continue
    m=$(jdk_major "$c"); [ -n "$m" ] && [ "$m" -ge 24 ] 2>/dev/null && { echo "$c"; return 0; }
  done
  return 1
}
phc_jar(){ # JMH jar (contains psu-auth-spi + Bouncy Castle): the copy saved in jmh/params, otherwise build/libs
  local j
  for j in "$C6_DATA"/jmh/params/*-jmh.jar "$JMH_DIR"/build/libs/*-jmh.jar; do [ -f "$j" ] && { echo "$j"; return 0; }; done
  return 1
}
phc_selftest(){ # prints one result line; 0 = passed
  local jdk jar out
  jdk=$(find_phc_jdk) || { echo "no JDK >= 24 with javac found (set PHC_JDK=<JDK 24 directory>)"; return 1; }
  jar=$(phc_jar) || { echo "no JMH jar (*-jmh.jar) in $C6_DATA/jmh/params or $JMH_DIR/build/libs"; return 1; }
  [ -f "$LT_DIR/R1C6PhcTool.java" ] || { echo "$LT_DIR/R1C6PhcTool.java not found"; return 1; }
  out=$(timeout 300 "$jdk/bin/java" -Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8 -cp "$jar" "$LT_DIR/R1C6PhcTool.java" selftest 2>&1 | tail -1)
  echo "$out"
  case "$out" in "SELFTEST OK"*) return 0 ;; *) return 1 ;; esac
}
# --- saved JMH jar: called at the start of every JMH step, BEFORE fresh_dir (wrong jar: stop before renaming anything)
jmh_jar_prepare(){
  if [ "$_JJ_DONE" = 1 ]; then
    [ -z "$JJ" ] || [ "$(md5sum "$JJ" | cut -c1-32)" = "$JJ_MD5" ] || die "JMH_JAR: $JJ changed between steps (md5 differs from $JJ_MD5)"
    return 0
  fi
  _JJ_DONE=1
  [ -n "$JMH_JAR" ] || { JJ=""; return 0; }
  local j="" want x
  if [ "$JMH_JAR" = saved ]; then for x in "$C6_DATA"/jmh/params/*-jmh.jar; do [ -f "$x" ] && { j=$x; break; }; done; else j=$JMH_JAR; fi
  [ -n "$j" ] && [ -f "$j" ] || die "JMH_JAR=$JMH_JAR: jar not found (saved copy: $C6_DATA/jmh/params/*-jmh.jar)"
  j=$(readlink -f "$j")
  want=$JMH_JAR_MD5
  [ -n "$want" ] || [ ! -f "$C6_DATA/jmh/params/jmh-jar.md5" ] || want=$(awk 'NR==1{print $1}' "$C6_DATA/jmh/params/jmh-jar.md5")
  [ -n "$want" ] || die "JMH_JAR: no md5 to check against ($C6_DATA/jmh/params/jmh-jar.md5 missing) - set JMH_JAR_MD5=<md5 of the jar>"
  JJ_MD5=$(md5sum "$j" | cut -c1-32)
  [ "$JJ_MD5" = "$want" ] || die "JMH_JAR: md5 of $j is $JJ_MD5, expected $want - no measurement"
  JJ=$j
  ok "JMH_JAR: $JJ (md5 $JJ_MD5 matches) - no SPI publication, no build"
  # a Gradle daemon left from an earlier build must not run in the background during the measurement
  local d; for d in "$JMH_DIR" "$BANK"; do
    [ -x "$d/gradlew" ] && ( cd "$d" && timeout 120 ./gradlew --stop -q >/dev/null 2>&1 ) && ok "gradlew --stop: ${d#"$REPO"/}"
  done
  return 0
}
setup_jvm(){
  say "[setup-jvm] JRE from $TEMURIN_IMAGE -> $TEMURIN_JRE"
  [ -x "$TEMURIN_JRE/bin/java" ] && { ok "present: $("$TEMURIN_JRE/bin/java" -version 2>&1 | grep -m1 Runtime)"; return 0; }
  mkdir -p "$(dirname "$TEMURIN_JRE")"
  local cid; cid=$(docker create "$TEMURIN_IMAGE" 2>/dev/null) || die "docker create $TEMURIN_IMAGE failed (network needed for the first pull)"
  docker cp "$cid:/opt/java/openjdk" "$TEMURIN_JRE" >/dev/null 2>&1; local rc=$?
  docker rm "$cid" >/dev/null 2>&1
  [ $rc -eq 0 ] && [ -x "$TEMURIN_JRE/bin/java" ] || die "docker cp failed"
  ok "$("$TEMURIN_JRE/bin/java" -version 2>&1 | grep -m1 Runtime)"
}

# --- the auth-server must run the indexed authorization store (IndexedInMemoryAuthorizationService) ---
as_store_line(){ kubectl --context bank-cluster-profile -n bank-cluster-nsp logs deploy/auth-server -c auth-server 2>/dev/null \
  | grep -m1 -o 'Authorization store: .*'; }
as_guard_line(){ kubectl --context bank-cluster-profile -n bank-cluster-nsp logs deploy/auth-server -c auth-server 2>/dev/null \
  | grep -m1 -o 'PAR_REQUEST_URI_GUARD active.*'; }
verify_as(){
  local line gl i; line=$(as_store_line); gl=$(as_guard_line)
  if [ -z "$line" ] || [ -z "$gl" ]; then
    # these lines are printed once at start-up; a pod that ran for a whole block may have rotated its log,
    # so the auth-server is restarted once and checked again. An image without these lines still stops here.
    # The same applies to the line "PAR_REQUEST_URI_GUARD active".
    warn "the auth-server log lacks 'Authorization store' or 'PAR_REQUEST_URI_GUARD active' (rotated log?) - restarting the auth-server to check again"
    kubectl --context bank-cluster-profile -n bank-cluster-nsp rollout restart deploy/auth-server >/dev/null 2>&1
    kubectl --context bank-cluster-profile -n bank-cluster-nsp rollout status deploy/auth-server --timeout=600s >/dev/null 2>&1
    for i in 1 2 3 4 5 6 7 8 9 10 11 12; do line=$(as_store_line); gl=$(as_guard_line); [ -n "$line" ] && [ -n "$gl" ] && break; sleep 5; done
  fi
  [ -n "$line" ] && ok "auth-server: $line" \
    || die "the auth-server does NOT run the indexed authorization store - run: ./run-R1C6.sh redeploy-as"
  [ -n "$gl" ] && ok "auth-server: $gl" \
    || die "the auth-server does NOT run ParRequestUriGuard - run: ./run-R1C6.sh redeploy-as"
}
redeploy_as(){
  say "[redeploy-as] rebuild the auth-server image + rollout (bank-cluster-profile)"
  clusters_up || die "clusters are not running (start them: cd $REPO && ./up.sh)"
  [ -f "$BANK/spring-cloud/authorization-server/src/main/java/sample/config/IndexedInMemoryAuthorizationService.java" ] \
    || die "IndexedInMemoryAuthorizationService.java not found in the auth-server sources"
  [ -f "$BANK/spring-cloud/authorization-server/src/main/java/sample/config/ParRequestUriGuard.java" ] \
    || die "ParRequestUriGuard.java not found in the auth-server sources"
  manifest redeploy-as
  ( cd "$BANK/kubernetes/scripts" && run_logged redeploy-as ./100-redeploy-bank-cluster.sh --images auth-server ) \
    || die "auth-server redeploy failed (see $C6_DATA/logs/redeploy-as.console.log)"
  kubectl --context bank-cluster-profile -n bank-cluster-nsp rollout status deploy/auth-server --timeout=300s >/dev/null 2>&1
  verify_as
}
clusters_up(){ kubectl --context bank-cluster-profile get nodes >/dev/null 2>&1 \
  && kubectl --context customer-cluster-profile get nodes >/dev/null 2>&1 \
  && kubectl --context tpp-cluster-profile get nodes >/dev/null 2>&1; }
stop_clusters(){ # isolation for the JMH steps that do not stop the clusters themselves (FBC)
  local p
  for p in bank-cluster-profile tpp-cluster-profile customer-cluster-profile; do
    minikube status -p "$p" 2>/dev/null | grep -q "host: Running" && { printf '   - minikube stop -p %s\n' "$p"; minikube stop -p "$p" >/dev/null 2>&1; }
  done
  return 0
}
fresh_dir(){ # $1 = result directory; existing data stops the step (FORCE=1: rename the old copy)
  # $2 ... = files of the step (params, logs): renamed with the same suffix; jmh/params/README.txt only once per command
  if [ -d "$1" ] && [ -n "$(ls -A "$1" 2>/dev/null)" ]; then
    [ "${FORCE:-0}" = 1 ] || die "$1 already holds data - check it; to measure again: FORCE=1 ./run-R1C6.sh ..."
    local sfx bak; sfx=".bak-$(date +%Y%m%d-%H%M%S)"; bak="$1$sfx"; mv "$1" "$bak"; warn "old copy renamed -> $bak"
    # rename the exported copy as well, so that export never mixes files of the old and the new measurement
    local ed="$EXPORT_DIR/${1#$C6_DATA/}" eb="$EXPORT_DIR/${bak#$C6_DATA/}"
    if [ -n "$EXPORT_DIR" ] && [ -d "$ed" ] && [ ! -e "$eb" ]; then
      mv "$ed" "$eb" && warn "exported copy renamed as well -> $eb" \
        || warn "cannot rename $ed - rename it by hand before the next export"
    fi
    # export copies both the .bak and the new files, so an overwritten file keeps its old content in the .bak copy
    local d=$1 f; shift
    for f in "$@"; do
      [ -f "$f" ] || continue
      if [ "$f" = "$C6_DATA/jmh/params/README.txt" ]; then [ "$_README_ROT" = 1 ] && continue; _README_ROT=1; fi
      mv "$f" "$f$sfx" && warn "renamed: ${f#"$C6_DATA"/} -> ${f#"$C6_DATA"/}$sfx"
    done
    set -- "$d"
  fi
  mkdir -p "$1"
}
run_logged(){ # $1 = log name; the rest = command
  local name=$1; shift
  "$@" 2>&1 | tee "$C6_DATA/logs/$name.console.log"
  return "${PIPESTATUS[0]}"
}

# --- parameters used: jmh/params, loadtest/params --------------------------------
params_readme(){ jmh_readme; lt_readme; }
jmh_readme(){
  { echo "# R1-C6 - JMH parameters of the campaign (wrapper run-R1C6.sh $(md5sum "$BANK/run-R1C6.sh" 2>/dev/null | cut -c1-32), written $(date -Iseconds))"
    echo "Measurement JVM: Temurin 24+36 ($TEMURIN_JRE, from $TEMURIN_IMAGE, same build as the auth-server); JAVA_HOME = JDK with javac for Gradle"
    echo "Forks/warm-up/measurement: FORKS=$J_FORKS  WI=$J_WI (x1 s)  IT=$J_IT (x1 s); taskset -c $J_CPUS; ISOLATE=$J_ISOLATE (three minikube clusters stopped)"
    echo "Steps:"
    echo "  main                  eval_jmh_final_manuscript_nipok.sh: seven mechanisms, -bm avgt -tu us -prof gc,"
    echo "                        -p group=elisabeth -p shaProvider=default -p sigProvider=elisabeth -p backend=sunjce"
    echo "  fbc-ab                eval_verify_nipok_fbc_normal.sh: NipokBenchmark.verify_server (Straus) and verify_server_prepared (FBC);"
    echo "                        three modes avgt (+gc), thrpt, sample"
    echo "  argon2id-sensitivity  eval_jmh_argon2_sensitivity.sh: Argon2SensitivityBenchmark (Bouncy Castle and libsodium, 13 configurations)"
    echo "  jvm-control           eval_jmh_jvm_control.sh: 5 benchmarks, ABBA GraalVM/Temurin/Temurin/GraalVM x 2 forks per block"
    echo "JMH jar: line env: JMH_JAR of every *.params.txt - empty = rebuilt by eval_*.sh; a path = saved jar, no build"
    echo "Exact parameters of every benchmark (mode, forks, warm-up, measurement, threads, @Param, JVM, JVM flags, JMH) read from the result JSON:"
    echo "  main.params.txt, fbc-ab.params.txt, argon2id-sensitivity.params.txt, jvm-control.params.txt"
  } > "$C6_DATA/jmh/params/README.txt"
}
lt_readme(){
  { echo "# R1-C6 - load-test parameters of the campaign (wrapper run-R1C6.sh $(md5sum "$BANK/run-R1C6.sh" 2>/dev/null | cut -c1-32), written $(date -Iseconds))"
    echo "## common variables (LT_COMMON) of every block and of the WAN phase"
    local kv; for kv in "${LT_COMMON[@]}"; do echo "   $kv"; done
    echo "## rate limiter during the measurement (RL_UP)"
    for kv in "${RL_UP[@]}"; do echo "   $kv"; done
    echo "## order of the mechanisms in the six blocks (Williams 6x6 for six units, seed 20261111; mtls always last; password_owasp right after password)"
    local i; for i in 1 2 3 4 5 6; do echo "   block$i: ${ORD[$i]}"; done
    echo "## password_owasp: same PASSWORD flow and PSU pwd-1; during the measurement the Argon2id PHC of pwd-1 = m=${PW_OWASP_M:-19456},t=${PW_OWASP_T:-2},p=${PW_OWASP_P:-1}"
    echo "   (password and every other phase: m=65536,t=3,p=1). Not measured in the WAN phase. The PHC parameters used are written to meta.txt"
    echo "   (password line: phc:, password_owasp: phc-swap:, phc-after:, phc-restore); commands and errors of the tool in phc-tool.log."
    echo "## wait for the auth-server to recover before the next run (SETTLE_* in LT_COMMON): the result of every wait is the line"
    echo "   '<mechanism>: settle(after <run>): ok|timeout <seconds> cpu=... probe=... rounds=...' of meta.txt; OutOfMemoryError lines"
    echo "   in the auth-server log of every run: authserver_log_oom_lines (summary.json); auth-server heap: line 'auth-server heap'."
    echo "## customer-agent memory 2Gi (AGENT_MEM in LT_COMMON; requests = limits; heap 512m); customer node >= ${NODE_MEM_MIN_MIB} MiB"
    echo "   (docker limit of the node: MANIFEST.txt line minikube nodes and meta.txt line agent tuning). For every run, summary.json has"
    echo "   restarts_in_run, restarts_in_run_n, agent_mem_peak_mib (peak since the pod was created), agent_mem_max_mib, agent_oom_kill_in_run,"
    echo "   agent_pod_changed_in_run, k6_conn_errors; anomalies add a line '<mechanism>: watch(<run>)' to meta.txt. The"
    echo "   agent-resources line also checks the memory. Reason: a 1Gi agent pod was OOM-killed at 768 VUs (password_owasp, 128 journeys/s)."
    echo "## load outside the measured system (NOISE_* in LT_COMMON): host_other_cores = busy cores of the WSL host - CPU of every container"
    echo "   of the three clusters - CPU of k6 (summary.json, with host_noisy). > NOISE_CORES: the noisy copy is kept (<run>.summary.json.noisy<n>,"
    echo "   .k6.log.noisy<n>) and the run repeated after NOISE_WAIT seconds + settle, at most NOISE_RETRY times; the kept summary.json has noise_retries;"
    echo "   meta.txt has a line '<mechanism>: noise(<run>)'. Reason: one knee confirmation run of nipok met 6.8 cores of foreign load"
    echo "   (knee 62). A watch warning is printed when data collection failed for more than 5% of the journeys."
    echo "## WAN phase (WAN_ARGS)"
    for kv in "${WAN_ARGS[@]}"; do echo "   $kv"; done
    echo "## files per step: block1.params.txt ... block6.params.txt, wan.params.txt"
    echo "   (variables passed in at the start + effective parameters and knee of every mechanism from meta.txt at the end)"
  } > "$C6_DATA/loadtest/params/README.txt"
}
jmh_params(){ # $1 = step (main|fbc-ab|argon2id-sensitivity|jvm-control); the rest = "KEY=value" passed by the wrapper
  local step=$1; shift
  local d="$C6_DATA/jmh/$step" pf="$C6_DATA/jmh/params/$step.params.txt"
  [ -d "$d" ] || return 0
  jmh_readme
  { echo "# R1-C6 - JMH parameters used: $step (written $(date -Iseconds))"
    echo "wrapper: run-R1C6.sh $(md5sum "$BANK/run-R1C6.sh" 2>/dev/null | cut -c1-32)"
    local kv; for kv in "$@"; do echo "env: $kv"; done
    [ -f "$d/env.txt" ] && { echo "## env.txt of the step"; sed 's/^/   /' "$d/env.txt"; }
    echo "## from the result JSON (each line: benchmark | mode | forks | warm-up | measurement | threads | @Param | JVM | JVM flags | JMH)"
    python3 - "$d" <<'PYPAR'
import glob, json, os, sys
d = sys.argv[1]
for f in sorted(glob.glob(os.path.join(d, "*.json"))):
    try:
        recs = json.load(open(f))
    except Exception:
        continue
    if not isinstance(recs, list) or not recs or "benchmark" not in recs[0]:
        continue
    print("   [%s] %d records" % (os.path.basename(f), len(recs)))
    for r in recs:
        p = r.get("params") or {}
        print("   %s | %s | f%s | %sx%s | %sx%s | t%s | %s | %s %s | %s | JMH %s" % (
            r["benchmark"].replace("bench.", ""), r.get("mode"), r.get("forks"),
            r.get("warmupIterations"), r.get("warmupTime"), r.get("measurementIterations"), r.get("measurementTime"),
            r.get("threads"), ",".join("%s=%s" % kv for kv in sorted(p.items())) or "-",
            r.get("jvm"), r.get("vmVersion", ""), " ".join(r.get("jvmArgs") or []) or "-", r.get("jmhVersion")))
PYPAR
  } > "$pf"
  ok "parameters: ${pf#$C6_DATA/}"
}
lt_params(){ # $1 = subdirectory (block1...|wan|pilot-*)  $2 = pre|post; the rest (pre) = extra variables passed in
  local sub=$1 ph=$2; shift 2
  local pf="$C6_DATA/loadtest/params/$sub.params.txt" mt="$C6_DATA/loadtest/$sub/meta.txt"
  if [ "$ph" = pre ]; then
    lt_readme
    { echo "# R1-C6 - load-test parameters: $sub (written at the start: $(date -Iseconds))"
      echo "wrapper: run-R1C6.sh $(md5sum "$BANK/run-R1C6.sh" 2>/dev/null | cut -c1-32) | run-all-psu.sh $(md5sum "$LT_DIR/run-all-psu.sh" 2>/dev/null | cut -c1-32) | bench-psu-auth.js $(md5sum "$LT_DIR/bench-psu-auth.js" 2>/dev/null | cut -c1-32)"
      echo "## environment variables passed to run-all-psu.sh (LT_COMMON + those of the step)"
      local kv; for kv in "${LT_COMMON[@]}" "$@"; do echo "   $kv"; done
    } > "$pf"
  else
    { echo "## effective parameters and knee of every mechanism (meta.txt at the end: $(date -Iseconds); detailed cgroup lines left out)"
      if [ -f "$mt" ]; then grep -v -E ': cgx |: cgroup probe:' "$mt" | sed 's/^/   /'; else echo "   (no meta.txt)"; fi
    } >> "$pf"
  fi
}
params_all(){ # rewrite every params file from existing results
  say "[params] $C6_DATA/jmh/params and $C6_DATA/loadtest/params"
  params_readme; ok "README.txt (jmh, loadtest)"
  local s d
  for s in main fbc-ab argon2id-sensitivity jvm-control; do [ -d "$C6_DATA/jmh/$s" ] && jmh_params "$s"; done
  for d in "$C6_DATA"/loadtest/*/; do
    s=$(basename "$d"); [ "$s" = params ] && continue
    [ -f "$d/meta.txt" ] || continue
    { echo "# R1-C6 - load-test parameters: $s (rewritten after the measurement by the params command, $(date -Iseconds))"
      echo "# the variables passed in at run time are not recorded by this step; see README.txt and meta.txt"; } > "$C6_DATA/loadtest/params/$s.params.txt"
    lt_params "$s" post; ok "parameters: loadtest/params/$s.params.txt"
  done
}
copy_logs(){ # $1 = prefix; the rest = raw log files copied into logs/
  local pre=$1 f; shift
  for f in "$@"; do [ -f "$f" ] && cp -p "$f" "$C6_DATA/logs/$pre.$(basename "$f")"; done
  return 0
}

jmh_main(){
  say "[jmh-main] JMH -> $C6_DATA/jmh/main"
  use_temurin; jmh_jar_prepare
  fresh_dir "$C6_DATA/jmh/main" "$C6_DATA/jmh/params/main.params.txt" "$C6_DATA/jmh/params/README.txt" \
    "$C6_DATA/logs/jmh-main.console.log" "$C6_DATA/logs/jmh-main.run.log" "$C6_DATA/logs/jmh-figs.console.log"
  manifest jmh-main
  ( cd "$JMH_DIR" && run_logged jmh-main env OUTDIR="$C6_DATA/jmh/main" FORKS="$J_FORKS" WI="$J_WI" IT="$J_IT" \
      ISOLATE="$J_ISOLATE" TASKSET_CPUS="$J_CPUS" JMH_JAR="$JJ" ./eval_jmh_final_manuscript_nipok.sh ) || die "jmh-main failed (see logs/jmh-main.console.log)"
  ok "done: $C6_DATA/jmh/main/official-final.json"
  jmh_params main OUTDIR="$C6_DATA/jmh/main" FORKS="$J_FORKS" WI="$J_WI" IT="$J_IT" ISOLATE="$J_ISOLATE" TASKSET_CPUS="$J_CPUS" JMH_JAR="$JJ" JMH_JAR_MD5="$JJ_MD5"
  copy_logs jmh-main "$C6_DATA/jmh/main/run.log"
  jmh_figs || warn "drawing the JMH figures failed - run it alone: ./run-R1C6.sh jmh-figs"
}
jmh_figs(){ # JMH figures in the layout of the paper (no title), FBC set: fig1_verify_logbar_fbc, fig2_pareto_fbc, fig4.1_radar_fbc
  local j="$C6_DATA/jmh/main/official-final.json" o="$C6_DATA/jmh/main/submission"
  [ -f "$j" ] || die "$j not found (run ./run-R1C6.sh jmh-main)"
  say "[jmh-figs] figures (SUBMISSION=1) from $j -> $o"
  mkdir -p "$o"
  ( cd "$JMH_DIR" && run_logged jmh-figs env OUT_DIR="$o" JSON_PATH="$j" NIPOK_VERIFY=verify_server_prepared FIG_SUFFIX=_fbc \
      JMH_CONFIG="-f$J_FORKS -wi$J_WI -i$J_IT" SUBMISSION=1 python3 eval_manuscript.py ) || return 1
  ok "done: $o (fig1_verify_logbar_fbc, fig2_pareto_fbc, fig4.1_radar_fbc ... .pdf/.png, tables_manuscript_fbc.md)"
}
jmh_fbc(){
  say "[jmh-fbc] A/B verify NIPoK normal vs FBC -> $C6_DATA/jmh/fbc-ab"
  use_temurin; jmh_jar_prepare
  fresh_dir "$C6_DATA/jmh/fbc-ab" "$C6_DATA/jmh/params/fbc-ab.params.txt" "$C6_DATA/jmh/params/README.txt" "$C6_DATA/logs/jmh-fbc.console.log"
  [ "$J_ISOLATE" = 1 ] && stop_clusters
  manifest jmh-fbc
  ( cd "$JMH_DIR" && run_logged jmh-fbc env RES="$C6_DATA/jmh/fbc-ab" FORKS="$J_FORKS" WI="$J_WI" IT="$J_IT" JMH_JAR="$JJ" \
      taskset -c "$J_CPUS" ./eval_verify_nipok_fbc_normal.sh ) || die "jmh-fbc failed (see logs/jmh-fbc.console.log)"
  ok "done: $C6_DATA/jmh/fbc-ab/fbc_ab_{avgt,thrpt,sample}.json"
  jmh_params fbc-ab RES="$C6_DATA/jmh/fbc-ab" FORKS="$J_FORKS" WI="$J_WI" IT="$J_IT" TASKSET="$J_CPUS" ISOLATE="$J_ISOLATE" JMH_JAR="$JJ" JMH_JAR_MD5="$JJ_MD5"
}
jmh_argon2(){
  say "[jmh-argon2] Argon2id sensitivity -> $C6_DATA/jmh/argon2id-sensitivity"
  use_temurin; jmh_jar_prepare
  fresh_dir "$C6_DATA/jmh/argon2id-sensitivity" "$C6_DATA/jmh/params/argon2id-sensitivity.params.txt" "$C6_DATA/jmh/params/README.txt" \
    "$C6_DATA/logs/jmh-argon2.console.log" "$C6_DATA/logs/jmh-argon2.run.log"
  manifest jmh-argon2
  ( cd "$JMH_DIR" && run_logged jmh-argon2 env OUTDIR="$C6_DATA/jmh/argon2id-sensitivity" FORKS="$J_FORKS" WI="$J_WI" IT="$J_IT" \
      ISOLATE="$J_ISOLATE" TASKSET_CPUS="$J_CPUS" JMH_JAR="$JJ" ./eval_jmh_argon2_sensitivity.sh ) || die "jmh-argon2 failed (see logs/jmh-argon2.console.log)"
  ok "done: $C6_DATA/jmh/argon2id-sensitivity/argon2id-sensitivity.json"
  jmh_params argon2id-sensitivity OUTDIR="$C6_DATA/jmh/argon2id-sensitivity" FORKS="$J_FORKS" WI="$J_WI" IT="$J_IT" ISOLATE="$J_ISOLATE" TASKSET_CPUS="$J_CPUS" JMH_JAR="$JJ" JMH_JAR_MD5="$JJ_MD5"
  copy_logs jmh-argon2 "$C6_DATA/jmh/argon2id-sensitivity/run.log"
}
jvm_control(){ # JVM control in one session: GraalVM CE 24 and Temurin 24+36, ABBA, 2 forks per block
  say "[jvm-control] JVM control (GraalVM CE 24 / Temurin 24+36, ABBA) -> $C6_DATA/jmh/jvm-control"
  [ -f "$JMH_DIR/eval_jmh_jvm_control.sh" ] || die "$JMH_DIR/eval_jmh_jvm_control.sh not found"
  [ -x "$TEMURIN_JRE/bin/java" ] || die "$TEMURIN_JRE not found - run first: ./run-R1C6.sh setup-jvm"
  [ -f "$C6_DATA/jmh/main/official-final.json" ] || warn "jmh/main/official-final.json not found - summary.txt will lack the column of this campaign"
  jmh_jar_prepare
  fresh_dir "$C6_DATA/jmh/jvm-control" "$C6_DATA/jmh/params/jvm-control.params.txt" "$C6_DATA/jmh/params/README.txt" \
    "$C6_DATA/logs/jvm-control.console.log" "$C6_DATA/logs/jvm-control.G1.log" "$C6_DATA/logs/jvm-control.T1.log" \
    "$C6_DATA/logs/jvm-control.T2.log" "$C6_DATA/logs/jvm-control.G2.log"
  manifest jvm-control
  ( cd "$JMH_DIR" && run_logged jvm-control env C6_DATA="$C6_DATA" OUT="$C6_DATA/jmh/jvm-control" REPO="$REPO" JMH_DIR="$JMH_DIR" \
      TEMURIN_JAVA="$TEMURIN_JRE/bin/java" WI="$J_WI" IT="$J_IT" TASKSET_CPUS="$J_CPUS" ISOLATE="$J_ISOLATE" JMH_JAR="$JJ" \
      bash ./eval_jmh_jvm_control.sh ) || die "jvm-control failed (see logs/jvm-control.console.log)"
  ok "done: $C6_DATA/jmh/jvm-control (G1/T1/T2/G2 .json + .log, env.txt, summary.txt)"
  jmh_params jvm-control OUT="$C6_DATA/jmh/jvm-control" WI="$J_WI" IT="$J_IT" TASKSET_CPUS="$J_CPUS" ISOLATE="$J_ISOLATE" FORKS_PER_BLOCK="${FORKS_PER_BLOCK:-2}" JMH_JAR="$JJ" JMH_JAR_MD5="$JJ_MD5"
  local b; for b in G1 T1 T2 G2; do copy_logs jvm-control "$C6_DATA/jmh/jvm-control/$b.log"; done
}

# docker memory limit of a minikube node (MiB; 0 = no limit; empty = cannot be read)
node_mem_mib(){ docker inspect "$1" --format '{{.HostConfig.Memory}}' 2>/dev/null | awk 'NR==1 && $1 ~ /^[0-9]+$/ {printf "%d", $1/1048576}'; }
node_mem_ok(){ local nm; nm=$(node_mem_mib "$CUST_NODE"); [ -n "$nm" ] && { [ "$nm" = 0 ] || [ "$nm" -ge "$NODE_MEM_MIN_MIB" ]; }; }
node_mem_txt(){ local nm; nm=$(node_mem_mib "$CUST_NODE"); if [ -n "$nm" ]; then echo "$nm MiB"; else echo "cannot be read (docker inspect $CUST_NODE)"; fi; }
# raise the docker memory limit of the customer node to NODE_MEM_MIN_MIB (live change, no cluster restart);
#   the same value is written to the minikube profile and to --memory of the customer cluster in 02-create-clusters.sh
#   (so that a node created later also has enough memory); every edited file is backed up as *.bak-R1C6-<time>.
fix_node_mem(){
  local c=$CUST_NODE want=$NODE_MEM_MIN_MIB cur cg cfg cs n ts; ts=$(date +%Y%m%d-%H%M%S)
  say "[fix-node-mem] node $c: docker memory limit -> ${want} MiB (agent pod 2 GiB + k8s control plane)"
  docker inspect "$c" >/dev/null 2>&1 || die "docker container $c not found"
  cur=$(node_mem_mib "$c")
  echo "   before: Memory=${cur:-?} MiB, MemorySwap=$(docker inspect "$c" --format '{{.HostConfig.MemorySwap}}' 2>/dev/null)"
  if [ -n "$cur" ] && { [ "$cur" = 0 ] || [ "$cur" -ge "$want" ]; }; then ok "node $c already has ${cur} MiB (0 = no limit): no change needed"
  else
    docker update --memory "${want}m" --memory-swap "${want}m" "$c" >/dev/null || die "docker update failed"
    cur=$(node_mem_mib "$c"); [ "$cur" = "$want" ] || die "after docker update: Memory=${cur:-?} MiB, not ${want}"
    ok "docker update: Memory=${cur} MiB, MemorySwap=$(docker inspect "$c" --format '{{.HostConfig.MemorySwap}}' 2>/dev/null)"
  fi
  cg=$(docker exec "$c" cat /sys/fs/cgroup/memory.max 2>/dev/null || true)
  echo "   inside the node: /sys/fs/cgroup/memory.max = ${cg:-cannot be read}"
  cfg="$HOME/.minikube/profiles/$c/config.json"
  if [ -f "$cfg" ]; then
    if python3 - "$cfg" "$want" "$cfg.bak-R1C6-$ts" <<'PY'
import json, shutil, sys
p, want, bak = sys.argv[1], int(sys.argv[2]), sys.argv[3]
d = json.load(open(p))
old = d.get("Memory")
if isinstance(old, int) and old >= want:
    print("   minikube profile: Memory=%d MB (sufficient, unchanged)" % old); sys.exit(0)
shutil.copy2(p, bak); d["Memory"] = want; json.dump(d, open(p, "w"), indent=4)
print("   minikube profile: Memory %s -> %d MB (backup %s)" % (old, want, bak))
PY
    then ok "minikube profile configuration: $cfg"; else warn "cannot edit $cfg (the running node has enough memory anyway)"; fi
  else warn "$cfg not found (skipped; the running node has enough memory anyway)"; fi
  cs="$BANK/kubernetes/scripts/02-create-clusters.sh"
  if [ -f "$cs" ]; then
    n=$(grep -c -- '--memory 2048' "$cs")
    if [ "$n" = 1 ]; then cp -p "$cs" "$cs.bak-R1C6-$ts" && sed -i "s/--memory 2048/--memory $want/" "$cs" \
      && ok "02-create-clusters.sh: customer cluster --memory 2048 -> $want (backup $(basename "$cs").bak-R1C6-$ts)"
    elif grep -q -- "--memory $want" "$cs"; then ok "02-create-clusters.sh already has --memory $want"
    else warn "02-create-clusters.sh: not exactly one line --memory 2048 (found $n) - unchanged; check the customer cluster yourself"; fi
  else warn "$cs not found (skipped)"; fi
  if node_mem_ok; then ok "node $c: $(node_mem_txt) >= $want MiB"; else die "node $c: $(node_mem_txt), still below $want MiB"; fi
  echo "   node memory now: $(docker stats --no-stream --format '{{.MemUsage}} ({{.MemPerc}})' "$c" 2>/dev/null)"
}
# agent check with the new memory: password_owasp (where the failure happened) and nipok, no confirm/refine; PASSES when every
#   run (warm-up included) has no restarted container, no OOM-killed agent, an unchanged agent pod and no k6 connection
#   error. Results in loadtest/stress-agent (rerun: FORCE=1 ...).
# The step runs STRAIGHT at 128 journeys/s (KNEE_RATES=128; maxVUs of bench-psu-auth.js = 6 x rate = 768), because a ladder
#   64,128 stops as soon as step 64 saturates (new auth-server pod, cold JVM) and step 128 never runs. A further PASS condition:
#   every selected mechanism has a kneestep128 run; for password_owasp and nipok (both reached 768 VUs at this step), its
#   k6.log must contain "reached 768 active VUs". STRESS_MECHS (default password_owasp,nipok) selects the mechanisms; other
#   mechanisms only print their VU count. password is not accepted: its knee ladder stops at 32 journeys/s, and 128
#   journeys/s with Argon2id m = 64 MiB only overloads the auth-server without testing the agent.
stress_agent(){
  local sm="${STRESS_MECHS:-password_owasp,nipok}" m
  for m in ${sm//,/ }; do
    case "$m" in
      private_key_jwt|password_owasp|nipok|ml_dsa|schnorr_interactive|ed25519|mtls) ;;
      password) die "STRESS_MECHS: password is not accepted (its knee ladder stops at 32 journeys/s; 128 journeys/s with Argon2id m = 64 MiB only overloads the auth-server)";;
      *) die "STRESS_MECHS: unknown mechanism '$m' (use: private_key_jwt,password_owasp,nipok,ml_dsa,schnorr_interactive,ed25519,mtls)";;
    esac
  done
  say "[stress-agent] $sm: straight at 128 journeys/s (maxVUs 768, the step that caused the OOM); results: loadtest/stress-agent"
  local st; st=$(phc_selftest) || die "password_owasp: R1C6PhcTool selftest failed: $st (see ./run-R1C6.sh check)"
  ok "phc-tool: ${st:0:150}"
  lt_run stress-agent stress-agent RUN_LABEL=stress-agent MECHS="$sm" PHASE=1 KNEE_RATES=128 \
    KNEE_CONFIRM=0 KNEE_REFINE=0 "${RL_UP[@]}"
  say "[stress-agent] results"
  if python3 - "$C6_DATA/loadtest/stress-agent" "$sm" <<'PY'
import glob, json, os, re, sys
d = sys.argv[1]; bad = n = 0; mechs = set()
need = [m for m in dict.fromkeys(sys.argv[2].split(",")) if m]   # selected mechanisms (STRESS_MECHS)
RATE = 128; CAP = 6 * RATE   # maxVUs of bench-psu-auth.js = 6 x rate
CAPREQ = {"password_owasp", "nipok"}   # these two mechanisms reached 768 VUs at step 128
hit = {m: [] for m in need}   # kneestep128 runs of every mechanism: (name, VUs reported by k6; None = cannot be read)
for f in sorted(glob.glob(os.path.join(d, "*.summary.json"))):
    try:
        s = json.load(open(f))
    except Exception:
        print("   %s: cannot be read" % os.path.basename(f)); bad += 1; continue
    n += 1; tag = os.path.basename(f)[:-len(".summary.json")]; mech = tag.split("-")[0]; mechs.add(mech)
    vu = ""
    if re.match(r"^[a-z0-9_]+-kneestep%d-r[0-9]+$" % RATE, tag):   # mechanism names may contain digits (ed25519)
        try:
            k6 = open(os.path.join(d, tag + ".k6.log"), encoding="utf-8", errors="replace").read()
            vmax = max([int(x) for x in re.findall(r"reached ([0-9]+) active VUs", k6)] or [0])
        except Exception:
            vmax = None
        if mech in hit:
            hit[mech].append((tag, vmax))
        vu = " vu-max=%s" % ("cannot be read" if vmax is None else ("%d" % vmax if vmax else "<%d" % CAP))
    ce = s.get("k6_conn_errors"); nce = None if ce is None else sum(ce.values())
    rs, oom, pc = s.get("restarts_in_run_n"), s.get("agent_oom_kill_in_run"), s.get("agent_pod_changed_in_run")
    pk, mx = s.get("agent_mem_peak_mib"), s.get("agent_mem_max_mib")
    pct = "" if not (pk and mx) else " (%.0f%%)" % (100.0 * pk / mx)
    print("   %-34s rps=%-7.2f http_req_failed=%-6s k6_conn_err=%-4s restarts=%-4s agent_oom=%-4s pod_changed=%-5s mem-agent=%s/%s MiB%s%s" % (
        tag, s.get("rps") or 0, s.get("http_req_failed_rate"), nce, rs, oom, pc, pk, mx, pct, vu))
    if rs is None or oom is None or nce is None or rs > 0 or oom > 0 or nce > 0 or pc:
        bad += 1
    if pk and mx and pk > 0.85 * mx:
        print("     ! agent memory peak above 85% of the limit (memory.peak includes reclaimable page cache)")
for m in need:   # every selected mechanism needs step 128; password_owasp and nipok must reach 768 VUs at that step
    if m not in mechs:
        print("   FAIL no result for: %s" % m); bad += 1
    elif not hit[m]:
        print("   FAIL %s: no run at step %d journeys/s (kneestep%d)" % (m, RATE, RATE)); bad += 1
    elif not any(v is not None and v >= CAP for _, v in hit[m]):
        if m in CAPREQ:
            print("   FAIL %s: step %d journeys/s did not reach %d VUs (k6.log lacks 'reached %d active VUs'): the load that caused the OOM was not reproduced" % (m, RATE, CAP, CAP)); bad += 1
        else:
            print("   (for reference) %s: step %d journeys/s did not reach %d VUs" % (m, RATE, CAP))
print("   %d runs, %d with a problem or unreadable" % (n, bad))
sys.exit(0 if n and not bad else 1)
PY
  then ok "stress-agent PASSED: every selected mechanism ran step 128 journeys/s (password_owasp, nipok reached 768 VUs); no container restarted, no agent OOM-kill, agent pod unchanged, no k6 connection error"
  else warn "stress-agent FAILED - see the lines above"; return 1; fi
}

lt_run(){ # $1 = subdirectory  $2 = log  the rest = extra environment variables
  local sub=$1 name=$2; shift 2
  clusters_up || die "clusters are not running (start them: cd $REPO && ./up.sh)"
  node_mem_ok || die "node $CUST_NODE: docker memory limit $(node_mem_txt), needs >= $NODE_MEM_MIN_MIB MiB (agent 2Gi) - run first: ./run-R1C6.sh fix-node-mem"
  [ "${REQUIRE_NEW_AS:-1}" = 1 ] && verify_as   # never measure on the old authorization store
  local jj="$C6_DATA/jmh/main/official-final.json" extra=()
  if [ -f "$jj" ]; then extra=(JMH_JSON="$jj"); else warn "no JMH result of this campaign ($jj) - the LT4 chart uses the default JSON"; fi
  local pj pc   # PHC tool for password_owasp
  if pj=$(find_phc_jdk 2>/dev/null) && pc=$(phc_jar 2>/dev/null); then
    extra+=(PHC_JAVA="$pj/bin/java" PHC_CP="$pc" PHC_TOOL="$LT_DIR/R1C6PhcTool.java")
  fi
  fresh_dir "$C6_DATA/loadtest/$sub" "$C6_DATA/loadtest/params/$sub.params.txt" "$C6_DATA/logs/$name.console.log"
  manifest "loadtest/$sub"
  lt_params "$sub" pre "$@" RESULTS="$C6_DATA/loadtest/$sub" "${extra[@]}"
  ( cd "$LT_DIR" && run_logged "$name" env "${LT_COMMON[@]}" "$@" RESULTS="$C6_DATA/loadtest/$sub" \
      "${extra[@]}" ./run-all-psu.sh ) || warn "run-all-psu.sh returned an error code (see logs/$name.console.log)"
  ok "results: $C6_DATA/loadtest/$sub ($(ls "$C6_DATA/loadtest/$sub"/*.summary.json 2>/dev/null | wc -l) summary.json)"
  lt_params "$sub" post; ok "parameters: loadtest/params/$sub.params.txt"
  # a mechanism skipped because the agent pod did not carry the CPU limit/request set (stuck rollout...) must be measured again
  grep -q "agent-resources: MISMATCH" "$C6_DATA/loadtest/$sub/meta.txt" 2>/dev/null \
    && warn "a mechanism was SKIPPED because the customer-agent pod did not carry the CPU/memory set - see the agent-resources line in meta.txt"
  return 0
}
pilot(){
  local which="${1:-all}"
  case "$which" in A|B|C|all) ;; *) die "pilot A|B|C (empty = all three)";; esac
  if [ "$which" = A ] || [ "$which" = all ]; then
    say "[pilot A] Schnorr, DEFAULT limiter (200 req/s/IP), knee only"
    lt_run pilot-A pilot-A RUN_LABEL=pilot-A MECHS=schnorr_interactive PHASE=1
  fi
  if [ "$which" = B ] || [ "$which" = all ]; then
    say "[pilot B] Schnorr, RAISED limiter (100000 req/s/IP), knee only"
    lt_run pilot-B pilot-B RUN_LABEL=pilot-B MECHS=schnorr_interactive PHASE=1 "${RL_UP[@]}"
  fi
  if [ "$which" = C ] || [ "$which" = all ]; then
    say "[pilot C] NIPoK, one full block, raised limiter"
    lt_run pilot-C pilot-C RUN_LABEL=pilot-C MECHS=nipok "${RL_UP[@]}"
  fi
}
block(){
  local n="${1:-}"
  [[ "$n" =~ ^[1-6]$ ]] || die "block N with N = 1..6"
  # a block with password_owasp needs a working PHC tool before it starts (~2.9 h)
  local st; st=$(phc_selftest) || die "password_owasp: R1C6PhcTool selftest failed: $st (see ./run-R1C6.sh check)"
  ok "phc-tool: ${st:0:150}"
  say "[block $n] order: ${ORD[$n]}"
  lt_run "block$n" "block$n" RUN_LABEL="block$n" MECHS="${ORD[$n]}" "${RL_UP[@]}"
}
wan(){
  say "[wan] RTT 0/20/50/100 ms, 3 runs per level, fixed 8 journeys/s, seven mechanisms (Fiat-Shamir trio first, mtls last)"
  # all seven mechanisms: the trio nipok, schnorr_interactive, ed25519 first and in a row; mtls last because it changes Istio
  lt_run wan wan "${WAN_ARGS[@]}" "${RL_UP[@]}"
}
status(){
  say "[status] $C6_DATA"
  local d
  for d in jmh/main jmh/fbc-ab jmh/argon2id-sensitivity jmh/jvm-control loadtest/pilot-A loadtest/pilot-B loadtest/pilot-C \
           loadtest/block1 loadtest/block2 loadtest/block3 loadtest/block4 loadtest/block5 loadtest/block6 loadtest/wan \
           loadtest/stress-agent; do
    if [ -d "$C6_DATA/$d" ] && [ -n "$(ls -A "$C6_DATA/$d" 2>/dev/null)" ]; then
      printf '   %-28s json=%-4s summary=%-4s %s\n' "$d" "$(ls "$C6_DATA/$d"/*.json 2>/dev/null | wc -l)" \
        "$(ls "$C6_DATA/$d"/*.summary.json 2>/dev/null | wc -l)" "$(grep -m1 '^end:' "$C6_DATA/$d/meta.txt" 2>/dev/null)"
    else printf '   %-28s (none)\n' "$d"; fi
  done
}
export_data(){
  [ -n "$EXPORT_DIR" ] || die "set EXPORT_DIR=<target directory> (for example a directory on another disk)"
  say "[export] $C6_DATA -> $EXPORT_DIR"
  [ -d "$(dirname "$EXPORT_DIR")" ] || die "$(dirname "$EXPORT_DIR") not found"
  mkdir -p "$EXPORT_DIR" && cp -r --preserve=timestamps "$C6_DATA/." "$EXPORT_DIR/" \
    && ok "copied ($(du -sh "$EXPORT_DIR" 2>/dev/null | cut -f1))" || die "copy failed"
}
check(){
  say "[check] files"
  local f; for f in "${FILES[@]}"; do [ -f "$f" ] && ok "$(md5sum "$f" | cut -c1-32)  ${f#$REPO/}" || warn "MISSING ${f#$REPO/}"; done
  if grep -q "^settle(){" "$LT_DIR/run-all-psu.sh" 2>/dev/null; then ok "run-all-psu.sh has SETTLE: waits for the auth-server to recover between runs"
  else warn "run-all-psu.sh lacks settle()"; fi
  if grep -q "^watch_snap(){" "$LT_DIR/run-all-psu.sh" 2>/dev/null; then ok "run-all-psu.sh has WATCH: restarts, OOM-kill, agent memory, k6 connection errors"
  else warn "run-all-psu.sh lacks watch_snap()"; fi
  say "[check] JVM"
  echo "   java on PATH: $(java -version 2>&1 | grep -m1 Runtime)"
  [ -x "$TEMURIN_JRE/bin/java" ] && ok "Temurin for JMH: $("$TEMURIN_JRE/bin/java" -version 2>&1 | grep -m1 Runtime)" || warn "$TEMURIN_JRE not found (./run-R1C6.sh setup-jvm)"
  find_build_jdk >/dev/null && ok "build JDK: $(find_build_jdk)" || warn "no JDK with javac found"
  say "[check] password_owasp: PHC tool"
  local pj pc st
  if pj=$(find_phc_jdk); then ok "JDK for R1C6PhcTool: $pj ($("$pj/bin/java" -version 2>&1 | grep -m1 -E 'Runtime Environment'))"
  else warn "no JDK >= 24 with javac found (set PHC_JDK=<JDK 24 directory>)"; fi
  if pc=$(phc_jar); then ok "jar JMH: $pc ($(md5sum "$pc" | cut -c1-32))"
  else warn "no JMH jar (*-jmh.jar): save the jar in jmh/params or rebuild crypto-jmh"; fi
  if st=$(phc_selftest); then ok "selftest: ${st:0:220}"; else warn "selftest FAILED: $st"; fi
  echo "   password_owasp is measured at m=19456 KiB, t=2, p=1; password and every other phase at m=65536, t=3, p=1"
  say "[check] saved JMH jar for JMH_JAR=saved"
  local sj="" sw sm x; for x in "$C6_DATA"/jmh/params/*-jmh.jar; do [ -f "$x" ] && { sj=$x; break; }; done
  if [ -n "$sj" ]; then
    sw=$(awk 'NR==1{print $1}' "$C6_DATA/jmh/params/jmh-jar.md5" 2>/dev/null); sm=$(md5sum "$sj" | cut -c1-32)
    if [ -n "$sw" ] && [ "$sm" = "$sw" ]; then ok "$sj md5 $sm (matches jmh/params/jmh-jar.md5)"
    else warn "$sj md5 $sm, jmh/params/jmh-jar.md5: ${sw:-none} - JMH_JAR=saved will stop (set JMH_JAR_MD5 if it is the right jar)"; fi
  else warn "no saved jar in $C6_DATA/jmh/params (*-jmh.jar)"; fi
  say "[check] cluster"
  clusters_up && ok "three clusters running" || warn "clusters are not running (JMH does not need them; the load test does)"
  if node_mem_ok; then ok "node $CUST_NODE: docker memory limit $(node_mem_txt) (needs >= $NODE_MEM_MIN_MIB MiB; 0 = no limit)"
  else warn "node $CUST_NODE: docker memory limit $(node_mem_txt), needs >= $NODE_MEM_MIN_MIB MiB - run ./run-R1C6.sh fix-node-mem before measuring"; fi
  if clusters_up; then local l; l=$(as_store_line)
    [ -n "$l" ] && ok "auth-server: $l" || warn "the auth-server does NOT run the indexed authorization store (./run-R1C6.sh redeploy-as)"
    l=$(as_guard_line)
    [ -n "$l" ] && ok "auth-server: $l" || warn "the auth-server does NOT run ParRequestUriGuard, or its log has rotated (./run-R1C6.sh redeploy-as)"
    # values for the description of resource isolation
    say "[check] nodes and customer-agent"
    echo "   k8s nodes: $(k8s_nodes)"
    echo "   reserved on the customer node: $(cust_allocated)"
    echo "   customer-agent (deployment): $(kubectl --context customer-cluster-profile -n customer-cluster-nsp get deploy customer-agent \
      -o jsonpath='{.spec.template.spec.containers[?(@.name=="customer-agent")].resources}' 2>/dev/null)"
    echo "   the load test sets: agent CPU limit=4 request=2, memory 2Gi (requests = limits), heap 512m (LT_COMMON)"
    echo "   customer node memory now (docker stats): $(docker stats --no-stream --format '{{.MemUsage}} ({{.MemPerc}})' "$CUST_NODE" 2>/dev/null)"
    # auth-server heap: a new JVM in the same container (same JAVA_TOOL_OPTIONS and RAM limit), nothing changed
    echo "   auth-server heap: $(kubectl --context bank-cluster-profile -n bank-cluster-nsp exec deploy/auth-server -c auth-server -- java -XX:+PrintFlagsFinal -version 2>/dev/null | awk '$2=="MaxHeapSize"{printf "MaxHeapSize=%d MiB", $4/1048576}') | JAVA_TOOL_OPTIONS=$(kubectl --context bank-cluster-profile -n bank-cluster-nsp get deploy/auth-server -o jsonpath='{.spec.template.spec.containers[?(@.name=="auth-server")].env[?(@.name=="JAVA_TOOL_OPTIONS")].value}' 2>/dev/null)"
  fi
  say "[check] measurement conditions"
  echo "   clocksource: $(cat /sys/devices/system/clocksource/clocksource0/current_clocksource 2>/dev/null || echo n/a)"
  echo "   swap: $(awk '/SwapTotal/{print $2" kB"}' /proc/meminfo) (must be 0 kB during measurements: sudo swapoff -a)"
  echo "   windows: $(win_info)"
  # read the three counters exactly as run-all-psu.sh will (3 samples, 1 s apart)
  local tp tpo; tp=$(winexe typeperf.exe) || tp=""
  if [ -z "$tp" ]; then
    warn "typeperf.exe cannot be called (WSL interop disabled?) - the win_cpu_* fields will be empty"
  else
    tpo=$(timeout 30 "$tp" "\\Processor Information(_Total)\\% Processor Time" "\\Processor Information(_Total)\\% Processor Utility" \
          "\\Processor Information(_Total)\\% Processor Performance" -si 1 -sc 3 2>&1 | tr -d '\r' | grep '^"[0-9]' | grep '[0-9]","[0-9]' | tail -1)
    if [ -n "$tpo" ]; then ok "typeperf.exe reads the three Windows CPU counters (Time, Utility, Performance): $tpo"
    else warn "typeperf.exe ($tp) cannot read the three CPU counters (Windows in another language?) - win_cpu_* will be empty"; fi
  fi
}

cmd="${1:-}"; shift || true
case "$cmd" in
  check)      check ;;
  setup-jvm)  setup_jvm ;;
  redeploy-as) redeploy_as ;;
  verify-as)  verify_as ;;
  jmh-main)   jmh_main ;;
  jmh-fbc)    jmh_fbc ;;
  jmh-argon2) jmh_argon2 ;;
  jvm-control) jvm_control ;;
  jmh-figs)   jmh_figs || die "drawing the JMH figures failed (see logs/jmh-figs.console.log)" ;;
  jmh-all)    jmh_main; jmh_fbc; jmh_argon2; jvm_control; warn "JMH done - start the clusters again: cd $REPO && ./up.sh" ;;
  params)     params_all ;;
  pilot)      pilot "${1:-all}" ;;
  block)      block "${1:-}" ;;
  wan)        wan ;;
  status)     status ;;
  export)     export_data ;;
  fix-node-mem) fix_node_mem ;;
  stress-agent) stress_agent ;;
  *) awk 'NR>1 {print} NR>1 && /^# ====/ && ++c==2 {exit}' "$0"; exit 1 ;;   # print the header of the file up to the second ==== line
esac
