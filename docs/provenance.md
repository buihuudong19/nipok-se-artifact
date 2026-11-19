# Provenance

This page states where each part of the repository comes from and how it relates to the code and data that produced the
results of the paper.

## Origin of each part

| Part | Origin | Changes for publication |
|---|---|---|
| `testbed/` | Working tree of the measurement host, archived on 19 November 2026 after the last measurement of the revision. It is the code that was deployed and measured in the campaigns of Sections 6.2.2 to 6.2.4. | See "Changes to the measured code" below |
| `formal/` | Models of version 2.0, unchanged in their model code | Comments corrected and translated into English; README rewritten; `run-all-formal.sh` also runs the two custody models (see `formal/README.md`) |
| `experiments/submission/` | Results published with version 2.0 | Folders renamed, logs moved to the raw-data archive (see its `README.md`) |
| `experiments/r1-c6-*`, `r1-c7-*`, `r1-c8-*` | Analysis scripts written for the revision | Comments and printed text in English; results regenerated from the raw data with these scripts |
| `docs/`, `README.md`, `CHANGELOG.md`, `CITATION.cff` | Written for version 3.0 | |

## Changes to the measured code

The files of `testbed/` differ from the measured tree in the following ways only:

- comments, printed messages and the labels of generated tables were translated into English, and decorative
  characters (box drawing, arrows, check marks) were replaced by ASCII;
- absolute paths of the measurement host were replaced by paths derived from the location of each script, and the
  command that copied raw data to a fixed folder of that host became `export` with a configurable `EXPORT_DIR`;
- deployment secrets were removed and are generated on the deployment host (`docs/secrets.md`); the scripts that used
  them read the generated values;
- `bank/benchmark/crypto-jmh/eval_manuscript.py` is the copy of the revision analysis that drew Figures 4-6 (95%
  confidence intervals over forks); the working tree held an earlier copy;
- `bank/run-R1C7.sh` creates the symbolic link of its load harness on first use instead of expecting it in the
  checkout;
- development helpers that took no part in the reported measurements were left out (listed below).

For every file, the program text was compared with the measured version after comments and the contents of string
literals were removed (Python: abstract syntax trees; Java, Gradle and JavaScript: source text; shell and YAML:
structure with variable expansions kept). The only files whose program text differs are those changed on purpose for
the points above; `CHANGELOG.md` lists them. Output strings that analysis scripts parse were kept unchanged, and where
a recorded file uses the old wording the analysis scripts accept both forms.

Class files rebuilt from this tree therefore differ from the measured JMH jars where a printed message was translated.
The jars that were measured, with their checksums, are in the `jmh/params` directories of the raw data, and the
`MANIFEST.txt` of each campaign records the md5 of the measured source files at every step.

Left out of the working tree: build output and caches, editor and tool settings, backup copies (`*.bak`), local key
material and certificates (all generated again by the setup scripts), packaged Helm dependencies (`charts/*.tgz`,
rebuilt by `helm dependency update`), the measurement output directories (`benchmark-R1-C*`, published as raw data),
a duplicate of a ProVerif model (the models are in `formal/`), development notes, Spring Initializr scaffolding and help
files, the Docker Compose set-up (not used by the Kubernetes testbed), and benchmark scripts for experiments not
reported in the paper (token-endpoint and ingress benchmarks, a PKI-variant switch, a profiling helper).

## Measured source files copied into the JMH benchmarks

The benchmarks of Section 6.2.3 (`testbed/bank/benchmark/crypto-jmh-c7`) do not depend on the service modules, so they
copy a few methods of the services statement by statement. Their Javadoc names each source file by an md5 prefix; the
full checksums of the measured versions are below (the files in this repository differ only in comments and messages).

| Prefix | md5 of the measured file | File (under `testbed/`) |
|---|---|---|
| 41213af6 | 41213af688d02cb66093b497fd00b3b8 | `bank/spring-cloud/authorization-server/src/main/java/sample/config/EdDsaJwtEncoder.java` |
| dd8b5ed1 | dd8b5ed131f2aabc36ac59f61904ffb9 | `bank/spring-cloud/authorization-server/src/main/java/sample/crypto/JcaEd25519SigningStrategy.java` |
| 4eabab95 | 4eabab953a3e055c58d9dc2a89cf0495 | `bank/spring-cloud/authorization-server/src/main/java/sample/jose/Jwks.java` |
| 45b43b58 | 45b43b588e0a4c3610af1269f14d5910 | `bank/services/customer-aggregator-service/src/main/java/com/openbanking/services/aggregator/customer/SecurityConfig.java` |
| 51efd2d2 | 51efd2d225f75d8c135bc2f928585445 | `bank/spring-cloud/authorization-server/src/main/java/sample/config/XfccClientCertificateFilter.java` |
| 049df1c1 | 049df1c1b25ce699c8ec05dcf2fc08b5 | `bank/psu-auth-spi/src/main/java/com/openbanking/psu/auth/spi/mtls/XfccParser.java` |
| 080225d6 | 080225d6a4cc754aefd4c54f91618e09 | `bank/spring-cloud/authorization-server/src/main/java/sample/config/JarmService.java` |
| 34fa8e40 | 34fa8e40bad02e9d1fd0ff04eef0bb3f | `tpp/services/tpp-service/src/main/java/com/openbanking/services/tpp/authcode/jarm/JarmValidator.java` |
| f514e04d | f514e04d1b91cd89ae5a52f64da885d7 | `bank/spring-cloud/authorization-server/src/main/java/sample/audit/SecurityAuditLogger.java` |
| b427e1e0 | b427e1e0721581712b6be1f65f790a98 | `bank/psu-auth-spi/src/main/java/com/openbanking/psu/auth/spi/wallet/SimulatorWalletProvider.java` |
| 059745f6 | 059745f6d2ce257cab50d5c0bcc78106 | `bank/spring-cloud/authorization-server/src/main/java/sample/psu/nipok/NipokChallengeStore.java` |
| a6d8100c | a6d8100c010f874e434e0ae581807f5b | `bank/spring-cloud/authorization-server/src/main/java/sample/psu/nipok/NipokAuthenticationProvider.java` |
| 90d0d1ec | 90d0d1ecc739d6b5453ca08a35b7da4e | `customer/services/customer-agent/src/main/java/com/openbanking/services/agent/customer/http/ChannelBinding.java` |

## Files of the conformance run

`experiments/r1-c8-conformance/run-conformance.sh check` prints the md5 of the files below. The published run used
these versions (`benchmark-R1-C8/MANIFEST.txt` in the raw data). The Java files of this repository differ from them
only in comments and messages; the two vector files are unchanged.

| md5 of the file in the published run | File (under `testbed/bank/psu-auth-spi/` unless stated) |
|---|---|
| c85df5338ada50dcd82917590d591cd1 | `src/main/java/com/openbanking/psu/auth/spi/crypto/nipok/NipokEncoding.java` |
| 58f213a49d09edff61548d6754d72528 | `src/main/java/com/openbanking/psu/auth/spi/crypto/nipok/NipokVerifier.java` |
| b427e1e0721581712b6be1f65f790a98 | `src/main/java/com/openbanking/psu/auth/spi/wallet/SimulatorWalletProvider.java` |
| a6d8100c010f874e434e0ae581807f5b | `testbed/bank/spring-cloud/authorization-server/src/main/java/sample/psu/nipok/NipokAuthenticationProvider.java` |
| b1aba28a9d7b3f93940f1127c87d2475 | `testbed/bank/spring-cloud/authorization-server/src/main/java/sample/psu/web/PsuRegistrationController.java` |
| 789062aeb0062c4205ef6363f38fc25e | `src/test/java/com/openbanking/psu/auth/spi/crypto/nipok/NipokC8Test.java` |
| a5d49673587d155b1175cff1c9a915c6 | `src/test/java/com/openbanking/psu/auth/spi/crypto/nipok/NipokC8VectorsTest.java` |
| 94dd3400d305098140e02fa3f3433a21 | `src/test/resources/nipok-test-vectors-v1.json` |
| e4e5909b1a7ec41e5a7774be65376d52 | `src/test/resources/nipok-test-vectors-v2.json` |

## Derived results

The derived results of `experiments/r1-c6-*` and `r1-c7-*` were regenerated from the raw data with the published
analysis scripts; `sources.md5` in each results directory lists the raw files read and `md5sums.txt` the files written.
Before publication they were compared with the output of the same scripts before translation: the figures are
byte-identical and the tables and data files contain the same numbers. For `r1-c8-conformance`, the JUnit reports and
the two Java vector reports are those of the run on the measurement host (Python 3.12.3 there); the Python reports and
the tables were regenerated with `run-conformance.sh vectors tables` and agree with that run except for the Python
version and the file paths they record (relative to the repository instead of absolute paths of the measurement host).
All regenerations used Python 3.11 with the packages of `experiments/requirements.txt`; the section "This run" of each
results `README.md` records the versions.

One input of Section 6.2.3 is kept as recorded rather than computed again. `benchmark-R1-C7/e2e/hops/hops.json`, which
gives the stages of Figure 10 and the requests and TLS connections per journey of Table 11, was written on the
measurement host by `testbed/bank/kubernetes/loadtest/k6-psu-c7/c7_hops.py`. The script takes the window of each k6 run
from the modification times of two marker files (`.<run>.cgx0` and `.<run>.cgx1`), and the raw-data archive keeps these
times only to the second. Run on the archive, the script therefore uses slightly different windows, and 181 of the
1,065 values of `hops.json` change slightly or appear in another order (in one run, for example, 61.0 s instead of
60.9 s and 3,361 instead of 3,368 requests). The derived results use the recorded `hops.json`, which is in the archive.

## Version tags in recorded files

Some recorded files carry the revision of the harness that wrote them, for example `(v3.6)` and `(v3.7)` in the
`meta.txt` and parameter files of Section 6.2.2, `C7Probe (R1-C7 v1.2)` in `probe.json` and `NipokC8VectorsTest
(R1C8-v1.1)` in the vector reports. They are kept as recorded, and the harnesses in this repository still write the
same tags, so that recorded files and new output have the same format.
