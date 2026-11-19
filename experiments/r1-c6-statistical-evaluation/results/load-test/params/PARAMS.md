# Load-test parameters (read from loadtest/params/*.params.txt)

## Variables passed to run-all-psu.sh (one value means identical in every block)

| Variable | Value |
|---|---|
| REPEATS | 3 |
| VUS | 16 |
| DURATION | 60s |
| WARMUP_RATE | 16 |
| KNEE_RATES | 4,8,16,32,64,128,256 |
| KNEE_DUR | 30s |
| KNEE_CONFIRM | 1 |
| KNEE_REFINE | 4 |
| KNEE_COOLDOWN | 10 |
| SWEEP | 1 |
| SWEEP_FRACS | 0.3,0.6,1.0 |
| SWEEP_REPEATS | 2 |
| TARGET_UTIL | 0.6 |
| RTT_SWEEP | 0 |
| CG_CPU | 1 |
| CGX_CPU | 1 |
| RL_COUNT | 1 |
| LOG_ERRORS | 1 |
| AGENT_CPU | 4 |
| AGENT_CPU_REQ | 2 |
| AGENT_MEM | 2Gi |
| SETTLE | 1 |
| SETTLE_CPU | 0.5 |
| SETTLE_INT | 3 |
| SETTLE_MAX | 600 |
| SETTLE_PROBE_MS | 5000 |
| NOISE_RETRY | 2 |
| NOISE_CORES | 2.5 |
| NOISE_WAIT | 60 |
| MECHS | block1: private_key_jwt,password,password_owasp,nipok,ml_dsa,schnorr_interactive,ed25519,mtls; block2: schnorr_interactive,nipok,ed25519,private_key_jwt,ml_dsa,password,password_owasp,mtls; block3: ml_dsa,ed25519,password,password_owasp,schnorr_interactive,private_key_jwt,nipok,mtls; block4: nipok,private_key_jwt,schnorr_interactive,password,password_owasp,ed25519,ml_dsa,mtls; block5: ed25519,schnorr_interactive,ml_dsa,nipok,password,password_owasp,private_key_jwt,mtls; block6: password,password_owasp,ml_dsa,private_key_jwt,ed25519,nipok,schnorr_interactive,mtls; wan: - |
| RL_PSU | 100000 |
| RL_PAR | 100000 |
| L8_ONLY | block1: -; block2: -; block3: -; block4: -; block5: -; block6: -; wan: 1 |
| RTT_MECHS | block1: -; block2: -; block3: -; block4: -; block5: -; block6: -; wan: nipok,schnorr_interactive,ed25519,password,private_key_jwt,ml_dsa,mtls |
| RTT_LIST | block1: -; block2: -; block3: -; block4: -; block5: -; block6: -; wan: 0,20,50,100 |
| RTT_REPEATS | block1: -; block2: -; block3: -; block4: -; block5: -; block6: -; wan: 3 |
| L8_FIXED_RATE | block1: -; block2: -; block3: -; block4: -; block5: -; block6: -; wan: 8 |

Paths (RESULTS, JMH_JSON, PHC_*) and RUN_LABEL are omitted from the table; see the raw files.

## Effective parameters recorded in block1.params.txt (main lines)

```
date: 2026-11-13T19:09:36+07:00
phase: all repeats: 3 vus: 16 util: 0.6
tuning: authcpu=4 sidecar=4 dbpool=50 agentcpu=4 agentcpureq=2 heap=512m
knee-search: rates=[4,8,16,32,64,128,256] dur=30s achieve>=0.90 fail<=0.05 confirm=1
agent tuning: cpu=4 (limit) request=2 mem=2Gi heap=512m (node customer: docker memory limit 4096 MiB (v3.7; 0 MiB = no limit), --cpus 3; docker does not limit the CPU of the node, see MANIFEST)
watch (v3.7): WATCH=1 (restartCount of every container in bank-cluster-nsp, customer-cluster-nsp, tpp-cluster-nsp; memory.peak/max/oom_kill of the agent pod; k6 connection errors; before and after every run)
host-cpu (v3.2): /proc/stat of the WSL VM before and after every run (host_cpu_*), CPU of k6 (k6_cpu_*), CLK_TCK=100
all-containers (v3.3): CGALL=1 (cgroup of every container on the 3 nodes) | windows-cpu: WIN_CPU=1 typeperf=/mnt/c/WINDOWS/system32/typeperf.exe
L1 sweep: SWEEP=1 fracs=[0.3,0.6,1.0] repeats=2 duration=60s
L8 rtt-sweep: RTT_SWEEP=0 rtt=[0,20,50] mechs=[nipok,schnorr_interactive,ed25519] repeats=3
verify-path: auth-server uses the FIXED-BASE COMB (NipokAuthenticationProvider → verifier.prepare(X)
swap: 0 kB
knee: refine=4 cooldown=10s | warmup rate=16
settle (v3.6): SETTLE=1 cpu<=0.5 core (mean over 3s) + probe journey <=5000ms (L8: +40 ms per ms of RTT), at most 600s
rate-limit (R1-C6): RL_PSU=100000 RL_PAR=100000
cpu-accounting: prometheus rate() over the run window + cgroup counter per run (CG_CPU=1)
```

## Effective parameters of the WAN phase (wan.params.txt, main lines)

```
date: 2026-11-15T04:52:36+07:00
phase: all repeats: 3 vus: 16 util: 0.6
tuning: authcpu=4 sidecar=4 dbpool=50 agentcpu=4 agentcpureq=2 heap=512m
knee-search: rates=[4,8,16,32,64,128,256] dur=30s achieve>=0.90 fail<=0.05 confirm=1
agent tuning: cpu=4 (limit) request=2 mem=2Gi heap=512m (node customer: docker memory limit 4096 MiB (v3.7; 0 MiB = no limit), --cpus 3; docker does not limit the CPU of the node, see MANIFEST)
watch (v3.7): WATCH=1 (restartCount of every container in bank-cluster-nsp, customer-cluster-nsp, tpp-cluster-nsp; memory.peak/max/oom_kill of the agent pod; k6 connection errors; before and after every run)
host-cpu (v3.2): /proc/stat of the WSL VM before and after every run (host_cpu_*), CPU of k6 (k6_cpu_*), CLK_TCK=100
all-containers (v3.3): CGALL=1 (cgroup of every container on the 3 nodes) | windows-cpu: WIN_CPU=1 typeperf=/mnt/c/WINDOWS/system32/typeperf.exe
L1 sweep: SWEEP=1 fracs=[0.3,0.6,1.0] repeats=2 duration=60s
L8 rtt-sweep: RTT_SWEEP=0 rtt=[0,20,50,100] mechs=[nipok,schnorr_interactive,ed25519,password,private_key_jwt,ml_dsa,mtls] repeats=3
verify-path: auth-server uses the FIXED-BASE COMB (NipokAuthenticationProvider → verifier.prepare(X)
swap: 0 kB
knee: refine=4 cooldown=10s | warmup rate=16
settle (v3.6): SETTLE=1 cpu<=0.5 core (mean over 3s) + probe journey <=5000ms (L8: +40 ms per ms of RTT), at most 600s
rate-limit (R1-C6): RL_PSU=100000 RL_PAR=100000
cpu-accounting: prometheus rate() over the run window + cgroup counter per run (CG_CPU=1)
```

