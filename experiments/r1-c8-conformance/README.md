# Conformance tests and interoperability (Section 6.2.4)

Test vectors for NIPoK, negative cases, and the parameters that a bank and an agent must share. Four implementations
run every vector: the Java verifier of the prototype with two group backends and two independent Python
implementations. The experiment answers Comment 8 of Reviewer 1.

| Part | Location |
|---|---|
| Test vectors | `testbed/bank/psu-auth-spi/src/test/resources/nipok-test-vectors-v2.json` (v1 kept alongside); built by `tools/gen_vectors_v2.py` |
| Java tests | JUnit in `testbed/bank/psu-auth-spi/src/test/java/com/openbanking/psu/auth/spi/crypto/` |
| Independent implementations | `tools/nipok_ref.py` (pure Python, standard library) and `tools/nipok_nacl_check.py` (PyNaCl/libsodium) |
| Driver | `run-conformance.sh` (`check`, `test`, `vectors`, `tables`); the testbed is not needed |
| Analysis | `analysis/c8_tables.py`, `analysis/c8_table_layout.py`; `analysis/templates/` holds the `README.md` and `MAPPING.md` written into the results |
| Derived results | `results/`: Tables 13 and 14, the `\Cei*` macros, JUnit reports and per-vector reports; `results/MAPPING.md` gives the file of every paper item |

The end-to-end rows of Table 13 and the testbed values of Table 14 come from Section 6.2.3 (Table 12 and `probe.json`
of its raw data). Regenerate the Python reports and the tables:

```bash
C7_PROBE=<raw>/benchmark-R1-C7/e2e/probe/probe.json ./run-conformance.sh check vectors tables
```

The step `test` runs the JUnit tests (JDK 24, Gradle, Maven Central; `libsodium` for the second backend).
