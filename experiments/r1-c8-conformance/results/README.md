# Results of the test vectors and negative cases (Reviewer 1, Comment 8)

This directory is written by `run-conformance.sh` (`test` writes `junit/` and the Java reports in `vectors/`; `vectors`
writes the Python reports; `tables` writes `tables/` and the files at the top level). `MAPPING.md` lists which file gives
which table or macro of the paper.

## What is checked

- Test vectors: `testbed/bank/psu-auth-spi/src/test/resources/nipok-test-vectors-v2.json` (valid proofs, invalid proofs,
  public keys for registration, stateful scenarios that cannot be static vectors, and deployment rules). Every v1 vector
  is kept in v2 with identical values; `tools/gen_vectors_v2.py` builds v2 from v1.
- Four implementations run every vector and must agree with the expected result and the rejection stage:
  1. the Java verifier of the prototype with the elisabeth backend (JUnit `NipokC8VectorsTest`);
  2. the same Java code with the libsodium backend (optional; needs `libsodium.so`);
  3. `tools/nipok_ref.py`, a pure-Python implementation written from the specification (standard library only);
  4. `tools/nipok_nacl_check.py`, point arithmetic and key validation from libsodium through PyNaCl (optional).
- JUnit (`junit/`): `NipokCryptoTest`, `NipokC8Test`, `NipokC8VectorsTest`, `LibsodiumEd25519GroupTest` on the code of
  `psu-auth-spi`.
- End-to-end rows of Table 13 come from Table 12 of Comment 7 (C7Probe through the real gateway); the testbed values of
  Table 14 (verifier identifier, nonce TTL, lockout, onboarding mode, channel binding of the gateway certificate) are
  checked against `probe.json` of Comment 7 and against the defaults in the source code.

## Layout

| Path | Contents |
|---|---|
| `junit/` | JUnit reports of the published run and `junit-summary.txt` |
| `vectors/` | per-vector reports: `java-vectors-elisabeth.json`, `java-vectors-libsodium.json`, `python-ref.{json,txt}`, `python-ref-v1.txt` (v1 vectors), `pynacl.{json,txt}` |
| `tables/` | `c8_vectors_all.csv` (one row per vector and implementation), `c8_conformance.csv` (one row per case), `c8_parameters.csv`, candidate bodies `table13_c8-conformance_rows.tex` and `table14_c8-parameters_rows.tex`, `c8_summary.txt` (every number with its source), `c8_tables.console.txt` |
| `tables/paper/` | bodies printed in the paper (`table13_c8-conformance_rows.tex`, `table14_c8-parameters_rows.tex`) and the `\Cei*` macros (`c8_macros.tex`), written by `analysis/c8_table_layout.py` from the files above |

The JUnit reports and the two Java reports are those of the published run on the measurement host; the Python reports and
the tables can be regenerated without Gradle (`run-conformance.sh vectors tables`).

## This run

- Python: 3.11.18; PyNaCl: 1.6.2
- Java backends of the JUnit run: 24 OpenJDK 64-Bit Server VM
- Inputs: sources.md5; outputs: md5sums.txt
