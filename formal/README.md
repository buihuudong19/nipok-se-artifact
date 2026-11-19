# NIPoK-SE: formal verification

This directory contains the formal models behind the security analysis
(Section 5) of the paper *A Privacy-Preserving Framework using Non-Interactive
Proofs of Knowledge for End-to-End Secure Authentication in Open Banking*.
The analysis is organized in three tiers, each of which discharges what the
tier above it assumes. Model names (D_Σ, G_auth, M_E2E, M_NIPoK, M_cust) are
those of the paper.

## Contents

| Tier | Tool | File | Model | Result |
|---|---|---|---|---|
| 3 | EasyCrypt | `easycrypt/SchnorrFS.ec` | D_Σ | Completeness, special soundness, and perfect special honest-verifier zero-knowledge (SHVZK) of the Schnorr Σ-protocol, machine-checked with no admitted step |
| 2 | CryptoVerif | `cryptoverif/nipok.cv` | G_auth | Injective agreement for the authentication step with an explicit bound, under the EUF-CMA security (UF-CMA in CryptoVerif's terms) of the proof |
| 1 | ProVerif | `proverif/nipok-e2e.pv` | M_E2E | Seven queries (S1, A1-A6) on the composed flow, in which NIPoK is combined with PAR/PKCE, JARM, certificate-bound access tokens, and RAR consent checks, for unboundedly many sessions |
| 1 | ProVerif | `proverif/nipok.pv` | M_NIPoK | Secrecy of the witness and injective agreement on (X, N, cb) for NIPoK alone |
| 1 | ProVerif | `proverif/custody-boundary.pv`, `proverif/custody-fulldump.pv` | M_cust (model pair) | The witness stays secret when the sealed blob on the heap is disclosed (first file) and is recovered once the off-heap key is disclosed as well (second file, a counterfactual) |

`run-all-formal.sh` runs all six files.

Two steps of the argument are classical results stated in the paper and are
not mechanized: the Fiat-Shamir reduction, which derives EUF-CMA security from
special soundness and SHVZK under the discrete-logarithm assumption in the
random oracle model (forking lemma), and the replacement of the uniformly
sampled prover nonce of D_Σ by the deterministic nonce of the implementation.

## Requirements

The three tools are installed with opam:

```bash
# opam and an OCaml switch (EasyCrypt requires OCaml >= 4.08 and < 5.0)
sudo apt-get install -y opam && opam init -y && eval $(opam env)
opam switch create 4.14.1 && eval $(opam env)

# Tiers 1 and 2
opam install -y proverif cryptoverif

# Tier 3: EasyCrypt from its GitHub repository, with the Alt-Ergo SMT solver
opam pin -yn add easycrypt https://github.com/EasyCrypt/easycrypt.git
opam install -y alt-ergo easycrypt
easycrypt why3config        # registers the installed SMT solvers
```

## Running

```bash
cd formal
./run-all-formal.sh
```

or one file at a time:

```bash
proverif proverif/nipok-e2e.pv
proverif proverif/nipok.pv
proverif proverif/custody-boundary.pv
proverif proverif/custody-fulldump.pv
cryptoverif cryptoverif/nipok.cv
rm -f easycrypt/SchnorrFS.eco && easycrypt compile easycrypt/SchnorrFS.ec
```

EasyCrypt records a successful check in `easycrypt/SchnorrFS.eco`. When this
cache is up to date, `easycrypt compile` returns at once without checking any
proof and prints nothing. Delete the cache before compiling, as above and in
`run-all-formal.sh`, so that every proof is checked again.

`nipok-e2e.pv` takes the longest; the paper reports convergence in under 150 s.

## Expected results

### ProVerif

ProVerif prints one `RESULT` line per query, followed by a verification summary.

`nipok-e2e.pv` (M_E2E): all seven queries hold.

| Id | Query in the file | Expected | Goal in the paper |
|---|---|---|---|
| S1 | `attacker(xPSU)` | `not attacker(xPSU[]) is true` | G0 |
| A1 | `inj-event(BankAccepts(pk(xPSU),n,cb)) ==> inj-event(PsuProves(pk(xPSU),n,cb))` | true | G4 |
| A2 | `inj-event(TokenIssued(t,code)) ==> inj-event(CodeIssued(code,ch))` | true | G5 |
| A3 | `event(TppGotCode(code)) ==> event(CodeIssued(code,ch))` | true | G6 |
| A4 | `event(RsGrants(t,c)) ==> event(TokenIssued(t,code))` | true | G7 |
| A5 | `event(RsGrantsResource(r)) ==> event(ConsentCovers(r))` | true | G8 |
| A6 | `event(RsGrantsAccountResource(o)) ==> event(ConsentCovers(o))` | true | G8 |

`nipok.pv` (M_NIPoK): both queries hold, namely `not attacker(xA[])` and
`inj-event(server_accepts(pk(xA),n,cb)) ==> inj-event(client_authenticates(pk(xA),n,cb))`.

`custody-boundary.pv` and `custody-fulldump.pv` (M_cust, query S2 of the paper):

```
custody-boundary.pv:   RESULT not attacker(x[]) is true.
custody-fulldump.pv:   RESULT not attacker(x[]) is false.
```

For `custody-fulldump.pv` the negative result is the intended outcome. ProVerif
reports that a trace has been found: the attacker reads both the sealed blob
`senc(x,kek)` and the off-heap key `kek` from the heap channel and applies `sdec`.

### CryptoVerif

```
RESULT Proved forall cb: cb_t, n: nonce, X: pkey; inj-event(bank_accepts(X, n, cb)) ==> inj-event(psu_proves(X, n, cb)) up to probability Psign(time_1, N) + 0.5 * N2^2 / |nonce|
All queries proved.
```

The replication parameters `N` and `N2` count the prover (PSU) and verifier
(bank) sessions, and `|nonce|` is the size of the nonce space. The bound is the
one stated in the paper, P_sign(t, q_P) + q_V²/(2|N|).

### EasyCrypt

With the cache deleted, `easycrypt compile easycrypt/SchnorrFS.ec` checks every
proof and exits with status 0. The lemmas `schnorr_completeness`,
`schnorr_special_soundness`, and `schnorr_shvzk` are proved without `admit`;
the `print` commands that follow the proofs display their statements.

## Modeling assumptions and abstractions

These points are stated in Section 5 of the paper and are summarized here.

- D_Σ (EasyCrypt). An abstract cyclic group of prime order (the primality
  of the order is an axiom of the development), an interactive challenge, and a
  uniformly sampled prover nonce. The edwards25519 encoding, the cofactor checks
  of the verifier, the hash function, and the deterministic nonce lie outside
  the model.
- G_auth (CryptoVerif). The proof is abstracted as a deterministic
  signature (`UF_CMA_det_signature`) over the context ctx(X, N, cb, id_V). The
  prover signs whatever channel-binding value the adversary presents to it,
  whereas the verifier uses the binding value of its own endpoint (`certS`).
  The model contains neither the wallet nor the OAuth exchange.
- ProVerif models. The proof is a symbolic term `nizk(x, ctx)` that
  verifies only under the same witness and context, and the Ed25519 signatures
  and the hash function are ideal. Each mTLS leg is a private channel, which
  assumes that TLS authenticates both ends and that the gateway forwards the
  client certificate faithfully; with a single shared channel, ProVerif does not
  terminate. The TLS endpoint of a PSU session is a fixed binding value, either
  `certS_cb` (direct connection to the bank) or the attacker's `certM`. Every
  authorization-server session draws a fresh nonce and accepts at most one
  proof. The enrolled key is preinstalled, and enrollment, re-enrollment,
  lockout, rate limiting, token expiry, and refresh tokens are not modeled.
  JARM is modeled as a signed message only: its JWE layer is not modeled in any
  model of this artifact, and its confidentiality is an assumption. The TPP
  follows the protocol but may request any resource or account.
- Identity binding. G_auth, M_NIPoK, and M_E2E bind the prover's key X and
  the verifier identity id_V but not the prover identifier id_P of the deployed
  context; this additional field can only shrink the set of contexts that an
  adversary can bring about.
- M_cust (ProVerif). The sealing is perfect symmetric encryption
  (`senc`/`sdec`), and the heap is a public channel that the attacker reads.
  The off-heap key `kek` is either kept off the heap (`custody-boundary.pv`) or
  written to it (`custody-fulldump.pv`).

The guarantees rest on the assumption stack of the paper: the discrete-logarithm
assumption in the prime-order subgroup of edwards25519; the random oracle model
for the challenge hash (SHA-512); EUF-CMA security of Ed25519 for the JARM and
access-token signatures; AEAD security of AES-256-GCM for the sealed wallet;
collision resistance of SHA-256 for PKCE; and the security of the TLS 1.3
channel from which the channel-binding value is derived.

### Counterfactual checks

- Deleting the check `if rReq = boundRes then` in process `RS` of
  `nipok-e2e.pv` makes A5 false, and deleting `if acctOwner = boundRes then` in
  process `RSAcct` makes A6 false; ProVerif then returns the corresponding
  attack traces.
- In `nipok.pv`, dropping cb from the context on both sides lets a proof made
  in one session be relayed into another (see the note at the end of the file).
- `custody-fulldump.pv` is the counterfactual of `custody-boundary.pv`.

## Changes since version 2.0

- This README has been rewritten in English and lists every model with its
  expected output. The README of version 2.0 reported five of the seven
  end-to-end queries and contained contradictory statements about admitted
  lemmas.
- `run-all-formal.sh` also runs the two custody models and deletes the
  EasyCrypt cache before compiling.
- The comments of the models have been corrected and translated into English.
  In `proverif/nipok-e2e.pv` they stated that the confidentiality of the JWE
  layer was proved in CryptoVerif, whereas no model of the artifact contains
  JWE; a header comment of `proverif/nipok.pv` now points to the counterfactual
  described at the end of the file. The model code of every file is unchanged
  from version 2.0.
- `easycrypt/SchnorrFS.eco`, a cache produced by EasyCrypt, is no longer
  included, and `*.eco` is listed in the top-level `.gitignore`.
- The top-level documentation refers to `formal/run-all-formal.sh`, the actual
  name of the script; version 2.0 called it `formal/run-all.sh`.
