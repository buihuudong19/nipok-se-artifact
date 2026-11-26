# Models prepared for version 3.1 and not yet run

**Status: none of the files listed here has been run through ProVerif or CryptoVerif.** They were prepared on a
machine on which no formal tool was installed. Their syntax was checked by reading only: each file is a copy of an
archived model that differs from it in the lines listed below, and every other line is identical to the archived
file. No statement of the paper may rest on these files until `./run-3.1.sh` has been run and its summary read.
Delete this file, or replace it by the summary of the run, when that is done.

The same holds for two edits of this version to files that the tools read: the header comment of
`cryptoverif/nipok.cv` and the comments of `easycrypt/SchnorrFS.ec` were changed (comments only; the code of both
files is unchanged), and both files must be run once more to confirm that they still load.

## 1. Copies with the prover identifier in the context

The archived models sign and check the reduced context (X, N, cb, id_V). The deployed context of the paper is
(X, id_P, N, cb, id_V). The three copies add id_P as the second field of the context wherever the context is built
or checked. The identifier is a public constant, `psuId`: each model enrolls one account, as before. The events and
the queries are unchanged, so the expected results are those of the archived models.

### `cryptoverif/nipok-idp.cv` (copy of `cryptoverif/nipok.cv`)

| Line of `nipok.cv` (this version; version 3.0: 7, 46, 48, 67, 78) | Archived | Copy | Reason |
|---|---|---|---|
| 7 (comment) | `context = (X, nonce_Bank, channel binding, verifierId).` | `context = (X, proverId, nonce_Bank, channel binding, verifierId).` | Describes the context of the copy. |
| 52 | `fun ctx(pkey, nonce, cb_t, host): signinput [data].` | `fun ctx(pkey, host, nonce, cb_t, host): signinput [data].` | The encoding takes the prover identifier as its second argument; `[data]` keeps it injective. |
| 54 | `const bankId: host.` | the same line, followed by `const psuId:  host.` | Declares the identifier of the enrolled account. |
| 73 | `out(cP2, sign(ctx(pkP, n, seenCb, bankId), skP)).` | `out(cP2, sign(ctx(pkP, psuId, n, seenCb, bankId), skP)).` | The prover signs the context with its identifier. |
| 84 | `if check(ctx(pkP, n, certS, bankId), pkP, s) then` | `if check(ctx(pkP, psuId, n, certS, bankId), pkP, s) then` | The verifier checks the context with the identifier of the enrolled account. |

Read against the unchanged parts: `host` is the type already used for `bankId`; `const <name>: <type>.` is the form
of the two declarations beside it; the two calls of `ctx` now have five arguments of types
`pkey, host, nonce, cb_t, host`, as declared. Seven comment lines were added at the top of the file.

### `proverif/nipok-idp.pv` (copy of `proverif/nipok.pv`)

| Line of `nipok.pv` | Archived | Copy | Reason |
|---|---|---|---|
| 43 | `free verifierId: bitstring.` | the same line, followed by `free psuId: bitstring.` | Declares the identifier of the enrolled account (public, like `verifierId`). |
| 66 | `let ctx = (pk(x), n, realCb, verifierId) in` | `let ctx = (pk(x), psuId, n, realCb, verifierId) in` | Context built by the PSU. |
| 75 | `let ctx = (X, n, certS, verifierId) in` | `let ctx = (X, psuId, n, certS, verifierId) in` | Context checked by the bank. |

### `proverif/nipok-e2e-idp.pv` (copy of `proverif/nipok-e2e.pv`)

| Line of `nipok-e2e.pv` | Archived | Copy | Reason |
|---|---|---|---|
| 49 | `free bankId: bitstring. free tppId: bitstring.` | the same line, followed by `free psuId: bitstring.` | Declares the identifier of the enrolled account. |
| 98 | `let ctx = (pk(xPSU), n, realCb, bankId) in` | `let ctx = (pk(xPSU), psuId, n, realCb, bankId) in` | Context built by the PSU. |
| 107 | `let ctxA = (pk(xPSU), n, certS_cb, bankId) in` | `let ctxA = (pk(xPSU), psuId, n, certS_cb, bankId) in` | Context checked by the authorization server. |

In both ProVerif copies the context is a tuple of type `bitstring`, so a fifth component needs no other declaration.
Seven comment lines were added at the top of each file.

What these copies do not add: a second account. With one enrolled account and a constant identifier, the copies
show that the proofs go through on the deployed encoding of the context. They do not show that a proof made for one
account is rejected for another account that shares its key; a model of that property needs two accounts and events
that carry the identifier, and its queries would differ from those printed in the paper.

### Expected results

| File | Expected |
|---|---|
| `cryptoverif/nipok-idp.cv` | `All queries proved.`, with the probability `Psign(time_1, N) + 0.5 * N2^2 / \|nonce\|`. CryptoVerif names its time bounds itself; if the name differs (`time_2`, for example) and the form of the bound is the same, read its definition in the output before accepting it. |
| `proverif/nipok-idp.pv` | `not attacker(xA[])` is true; the injective agreement is true. |
| `proverif/nipok-e2e-idp.pv` | The seven queries S1 and A1 to A6 are true. Measure the run time; the paper reports 0.014 s for the archived model. |

## 2. Mutation copies of `proverif/nipok-e2e.pv`

The paper says of queries A2 and A4 that they follow from the structure of the processes and from the private
channels, and that they depend neither on the PKCE check, nor on the certificate-binding check, nor on the token
signature. That statement was read from the model. The four copies in `proverif/mutations/` test it: each deletes
one or two checks and changes nothing else (seven comment lines are added at the top). They are not models of the
protocol.

| File | Deleted lines of `nipok-e2e.pv` | Process |
|---|---|---|
| `nipok-e2e-no-code-pkce.pv` | 117 `if codeIn = code then` and 118 `if H(verifier) = pkceChallenge then` | AS, token endpoint |
| `nipok-e2e-no-pkce.pv` | 118 only | AS, token endpoint |
| `nipok-e2e-no-sig-cnf.pv` | 147 `if checksign(mt, token, spk(skTok)) = true then` and 149 `if boundCnf = presentedCnf then` | RS |
| `nipok-e2e-no-cnf.pv` | 149 only | RS |

The first and the third file are the two runs asked for; the second and the fourth separate the two checks of each
pair if a result differs. After each deletion the next line continues the same process (`new tok:bitstring;` after
the input of the token request; `let (tok, boundCnf, boundRes) = mt in` and `event RsGrants(...)` after
`let mt = getmsg(token) in`). The deleted lines bind no variable, so every later use of a variable is still bound.

Expected: all seven queries stay true in the four copies. Reasons, for the two queries in question:

- A2, `inj-event(TokenIssued(t,code)) ==> inj-event(CodeIssued(code,ch))`. Both events are executed by the same
  session of the AS, `CodeIssued` first, with the code that this session created with `new`. A session executes
  `TokenIssued` at most once. Neither deleted line is needed for this.
- A4, `event(RsGrants(t,c)) ==> event(TokenIssued(t,code))`. The RS reads the token from the private channel
  `cRs`. Only the TPP writes to it, and the TPP forwards what it read from the private channel `cTokR`, to which
  only the AS writes, after `TokenIssued`. The attacker cannot write to either channel, so the signature check and
  the binding check reject nothing in this model.

`RSAcct` keeps its checks in all four copies; A6 is not under test.

## 3. Running

```bash
cd formal
./run-3.1.sh          # all archived models, the three copies, the four mutation copies
```

The script writes `results-3.1/summary.md` (one row per query: expected, observed, verdict, seconds),
`results-3.1/versions.txt` (tool versions and machine) and the complete output of each run in `results-3.1/logs/`.
Its exit status is 0 when every query has its expected outcome. Copy the versions into the table "Tool versions and
machine of the published runs" of `README.md`.

## 4. What to change in the paper for each outcome

Section, table and line references are to the long revised version of 23 Nov 2026 (`5-security-analysis.tex`,
`7-conclusion.tex`); the wording to look for is quoted, because the numbers move when the text is shortened.

### 4.1 Copies with id_P

**Outcome A: the three copies give the expected results.** Then the models were run on the deployed context, with
one enrolled account. Change:

1. Section "A Three-Tier Verification Framework". Replace
   "$\mathcal{G}_{\mathrm{auth}}$, $\mathcal{M}_{\mathrm{NIPoK}}$, and $\mathcal{M}_{\mathrm{E2E}}$ were run on the
   reduced context $\mathsf{ctx}^{-}$ of \S\ref{subsec:tier2}, which omits $\mathrm{id}_P$; none was run on the
   deployed context. We expect the argument to apply there, since $\mathrm{id}_P$ is one more field of an
   injectively encoded message, but no model covers the separation of accounts under a shared key that
   $\mathrm{id}_P$ adds."
   by
   "$\mathcal{G}_{\mathrm{auth}}$, $\mathcal{M}_{\mathrm{NIPoK}}$, and $\mathcal{M}_{\mathrm{E2E}}$ were run on the
   deployed context, in which $\mathrm{id}_P$ is a fixed public field. Each model enrolls a single account, so no
   model covers the separation of accounts under a shared key that $\mathrm{id}_P$ adds."
   The second sentence must stay: the copies do not test that property (Section 1 above).
   In the same paragraph, "a deterministic signature over $\mathsf{ctx}^{-}$ (\S\ref{subsec:tier2})" becomes
   "a deterministic signature over $\mathsf{ctx}$ (\S\ref{subsec:tier2})".
2. Table "claims and scope", row "Authentication step": delete ", context without $\mathrm{id}_P$".
3. Section "Tier 2". "of the reduced context $\mathsf{ctx}^{-}=(X,N,\mathit{cb},\mathrm{id}_V)$" becomes "of the
   context $\mathsf{ctx}=(X,\mathrm{id}_P,N,\mathit{cb},\mathrm{id}_V)$". Delete the sentence "The deployed
   challenge of \S\ref{subsec:nipok-protocol} folds in one field more, $\mathrm{id}_P$, on which no model was run
   (\S\ref{subsec:framework})." In the injective-agreement experiment, "returns the proof on $\mathsf{ctx}^{-}$
   with $(N,\mathit{cb})=(N',\mathit{cb}')$" becomes "returns the proof on $\mathsf{ctx}$ with
   $(N,\mathit{cb})=(N',\mathit{cb}')$ and the identifier of the enrolled account". After these edits
   $\mathsf{ctx}^{-}$ should occur nowhere; check with a search.
4. Table of the ProVerif outcomes, part (a), row "Identity binding": in the three cells, "$X$ and $\mathrm{id}_V$;
   $\mathrm{id}_P$ omitted" becomes "$X$, $\mathrm{id}_P$ and $\mathrm{id}_V$; one enrolled account".
5. Conclusion. Replace "The formal models omit the prover identifier, whose binding is tested
   (Table~\ref{tab:c7-lifecycle}) but not modeled." by "The formal models enroll a single account; the separation
   of accounts by the prover identifier is tested (Table~\ref{tab:c7-lifecycle}) but not modeled."
6. The paper reports 0.014 s for the archived model (Section 5.5). If the run time of `nipok-e2e-idp.pv` differs
   from it by more than the spread of three runs, report both times and name the machine.
7. In this package: make the three copies the models that `README.md` lists under "Contents" and "Expected
   results", keep the archived files as the models of version 3.0, and rewrite the entry "Identity binding" of
   `README.md` in the words of item 1.

**Outcome B: a copy does not load (syntax or type error).** This is a defect of the copy and not a result. Correct
the line that the tool names, run again, and record the correction here. The paper does not change.

**Outcome C: a query of a copy is false or cannot be proved, CryptoVerif does not prove the query, or the bound has
another form.** The paper keeps the reduced context everywhere, and the sentence "none was run on the deployed
context. We expect the argument to apply there, since $\mathrm{id}_P$ is one more field of an injectively encoded
message, but" is no longer accurate. Replace it by a statement of what was observed, for example: "On the deployed
context, <tool> does not prove <query> of <model> (<outcome reported by the tool>); the results of this section are
those of the reduced context, and no model covers the separation of accounts under a shared key that
$\mathrm{id}_P$ adds." Do not keep "We expect the argument to apply there". Keep the log.

**Outcome D: ProVerif does not terminate on `nipok-e2e-idp.pv` within the time limit.** Same as outcome C, with
"did not terminate within <time> on <machine>" as the observation.

### 4.2 Mutation copies

**Outcome A: A2 and A4 are true in the four copies.** The sentence "A2 and~A4 follow from the structure of the AS
and RS processes and from the private channels on which tokens travel; they depend neither on these two checks nor
on the token signature." is confirmed. Optional addition at its end: ", as runs of the model without them confirm".
The cells of A2 and A4 in the table of queries stand.

**Outcome B: A2 is false or cannot be proved in `nipok-e2e-no-code-pkce.pv`.** Read `nipok-e2e-no-pkce.pv`. If A2
is true there, A2 depends on the comparison of the code and not on PKCE: replace "they depend neither on these two
checks nor on the token signature" by "A4 depends neither on these two checks nor on the token signature; A2 holds
with the comparison of the presented code in place and does not depend on the PKCE check", and in the table of
queries, row A2, replace "it does not exercise the PKCE check that the model contains" accordingly. If A2 differs
in `nipok-e2e-no-pkce.pv` as well, A2 depends on the PKCE check: delete "like the PKCE check" from the sentence
before, state that A2 exercises the PKCE check, and correct the cell of A2.

**Outcome C: A4 is false or cannot be proved in `nipok-e2e-no-sig-cnf.pv`.** Read `nipok-e2e-no-cnf.pv`. If A4 is
true there, A4 depends on the token signature: replace "nor on the token signature" by a statement that A4 holds
with the signature check in place, and in the table of queries, row A4, replace "the token signature is checked in
the model but exercised by no query". If A4 differs in `nipok-e2e-no-cnf.pv` as well, A4 depends on the
certificate-binding check, and the sentence "The sender-constraining of tokens, like the PKCE check, is present in
the model but exercised by no query" must be corrected with the cell of A4.

**Outcome D: another query differs in a mutation copy.** Report it with the log before any change of the text. In
`nipok-e2e-no-sig-cnf.pv`, A5 is expected to stay true for the reason given for A4; a false A5 there would mean
that the consent query rests on the token signature.

"Cannot be proved" is not "false": ProVerif then has neither a proof nor an attack, and the text may claim neither.
