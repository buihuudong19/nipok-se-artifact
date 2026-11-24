(* ============================================================================ *)
(*  SchnorrFS.ec - EasyCrypt (LAYER 3, primitive): NIPoK = Schnorr Σ-protocol      *)
(*  + Fiat-Shamir.                                                                *)
(*                                                                               *)
(*  REAL PROOFS (no admit, type-checked) - NIPoK is a secure Σ-protocol:          *)
(*    - Completeness          - an honest prover is always accepted.              *)
(*    - Special soundness     - EXTRACTOR: 2 transcripts with the same a and different e => *)
(*                              witness w=(z−z')/(e−e')  => knowledge soundness.  *)
(*    - SHVZK                 - the SIMULATOR produces identically distributed transcripts *)
(*                              WITHOUT w => zero knowledge.                      *)
(*  Special soundness and SHVZK are the two properties of the protocol from which  *)
(*  the classical Fiat-Shamir argument derives, under the discrete-logarithm (DL)  *)
(*  assumption in the random oracle model, the UF-CMA property that CryptoVerif    *)
(*  takes as its premise. That argument is stated in the paper and is NOT          *)
(*  mechanized in this file, which treats the interactive protocol only.           *)
(*                                                                               *)
(*  NIPoK mapping: statement h = X = g^x (public key) ; witness w = x (PSU scalar); *)
(*    R_DL h w <=> h = g^w (possession of the discrete log). challenge e = Fiat-Shamir hash. *)
(*                                                                               *)
(*  ORIGIN: adapted from examples/SchnorrPK.ec of the EasyCrypt distribution       *)
(*    (https://github.com/EasyCrypt/easycrypt). The declarations, the module       *)
(*    SchnorrPK, the lemmas and their proof scripts come from that file. Compared  *)
(*    with the file on the main branch of EasyCrypt on 24 Nov 2026, the code       *)
(*    differs in the names of the four lemmas (the prefix                         *)
(*    schnorr_proof_of_knowledge_ is shortened to schnorr_) and in one step of     *)
(*    the completeness proof; the comments, which relate the development to       *)
(*    NIPoK, were added. EasyCrypt is distributed under the MIT license; its      *)
(*    copyright and permission notice is reproduced below.                        *)
(*  >>> TO FILL BY THE FIRST AUTHOR BEFORE RELEASE <<<                             *)
(*    EasyCrypt commit of the examples/SchnorrPK.ec that was adapted, and with     *)
(*    which this file was checked:  ________________________________________       *)
(*    (then compare the notice below with the LICENSE file at that commit)        *)
(*  RUN:  easycrypt compile easycrypt/SchnorrFS.ec   -> 3 prints (proven).        *)
(*                                                                               *)
(*  KEY CUSTODY: the witness `w=x` is generated in `keygen` (`w <$ dt`) and held by *)
(*    the wallet; `R_DL h w` = possession of the discrete log. SHVZK (proven) => the proof does NOT leak x; *)
(*    where x is STORED (simulator SEALED/off-heap, Kubernetes Secret, TEE) lies BELOW the abstraction - *)
(*    the model is invariant to the backend. At-rest/host dumps are outside the computational scope. *)
(* ============================================================================ *)
(* ---------------------------------------------------------------------------- *)
(*  Copyright and permission notice of EasyCrypt (file LICENSE of its repository, *)
(*  as read on its main branch on 24 Nov 2026), which covers the parts of this    *)
(*  file taken from examples/SchnorrPK.ec:                                        *)
(*
   MIT License

   Copyright (c) 2012 IMDEA Software Institute
   Copyright (c) 2012 Inria
   Copyright (c) 2017 École Polytechnique
   Copyright (c) EasyCrypt contributors (see AUTHORS)

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*)
(* ---------------------------------------------------------------------------- *)
require import Int.
require import Real.
require import Distr.
require (****) Group.

clone Group.CyclicGroup as G.

axiom prime_p : IntDiv.prime G.order.

clone G.PowZMod as GP with
  lemma prime_order <- prime_p.

clone GP.FDistr as FD.

clone GP.ZModE.ZModpField as ZPF.

import G GP GP.ZModE FD.

require (*--*) SigmaProtocol.

(* -- NIPoK types = Schnorr Σ-protocol --------------------------------------- *)
theory SchnorrTypes.
  type statement = group.        (* X = g^x : public key of the PSU *)
  type witness   = exp.          (* x : secret scalar (NIPoK private key) *)
  type message   = group.        (* V = g^v : commitment *)
  type secret    = exp.          (* v : ephemeral *)
  type challenge = exp.          (* e = H(g‖V‖X‖ctx) : Fiat-Shamir *)
  type response  = exp.          (* s = v + e·x  (sign + here; NIPoK uses v−ex, equivalent) *)

  op R_DL (h : group) (w : exp) = (h = g ^ w).   (* relation: possession of the discrete log *)
end SchnorrTypes.
export SchnorrTypes.

clone import SigmaProtocol as SP with
  type SigmaProtocol.statement <- statement,
  type SigmaProtocol.witness   <- witness,
  type SigmaProtocol.message   <- message,
  type SigmaProtocol.secret    <- secret,
  type SigmaProtocol.challenge <- challenge,
  type SigmaProtocol.response  <- response,
  op   SigmaProtocol.R         = R_DL,
  op   SigmaProtocol.de        = dt.
export SigmaProtocol.

(* -- NIPoK scheme (Schnorr) ------------------------------------------------- *)
module SchnorrPK : SigmaScheme = {
  proc gen() : statement * witness = {
    var h, w;
    w <$ dt;
    if (w = GP.ZModE.zero) {
      w <- GP.ZModE.zero;
    }
    h <- g ^ w;
    return (h, w);
  }
  proc commit(h: statement, w: witness) : message * secret = {
    var r, a;
    r <$ dt;                       (* v <- CSPRNG *)
    a <- g ^ r;                    (* V = g^v *)
    return (a, r);
  }
  proc test(h: statement, a: message) : challenge = {
    var e;
    e <$ dt;                       (* (interactive) random e; FS replaces it with H *)
    return e;
  }
  proc respond(sw: statement * witness, ms: message * secret, e: challenge) : response = {
    var z, w, r;
    w <- snd sw;
    r <- snd ms;
    z <- r + e * w;                (* s = v + e·x *)
    return z;
  }
  proc verify(h: statement, a: message, e: challenge, z: response) : bool = {
    var v, v';
    v <- a * (h ^ e);              (* V · X^e *)
    v' <- g ^ z;                   (* g^s *)
    return (v = v');               (* g^s ?= V·X^e *)
  }
}.

module SchnorrPKAlgorithms : SigmaAlgorithms = {
  (* EXTRACTOR (special soundness): extracts the witness x from 2 forked transcripts *)
  proc soundness(h: statement, a: message, e: challenge, z: response, e': challenge, z': response) : witness option = {
    var sto, w, v, v';
    v  <- (g ^ z  = a * (h ^ e));
    v' <- (g ^ z' = a * (h ^ e'));
    if (e <> e' /\ v /\ v') {
      w <- (z - z') / (e - e');    (* x = (s−s')/(e−e') mod ℓ *)
      sto <- Some(w);
    } else {
      sto <- None;
    }
    return sto;
  }
  (* SIMULATOR (SHVZK): produces a valid transcript without x *)
  proc simulate(h: statement, e: challenge) : message * challenge * response = {
    var a, z;
    z  <$ dt;
    a  <- (g ^ z) * (h ^ (-e));    (* V = g^s · X^(−e) => same distribution as the real one *)
    return (a, e, z);
  }
}.

section SchnorrPKSecurity.
  (* (1) Completeness - an honest prover always passes *)
  lemma schnorr_completeness_ll:
    islossless Completeness(SchnorrPK).main.
  proof. by islossless; apply FDistr.dt_ll. qed.

  lemma schnorr_completeness h w' &m:
    R h w' =>
    Pr[Completeness(SchnorrPK).main(h, w') @ &m : res] = 1%r.
  proof.
    rewrite /R /R_DL; move => sigmarel.
    byphoare (_: h = x /\ w' = w ==> _) => //; rewrite sigmarel.
    proc; inline*; swap 3 -2; swap 8 -7.
    wp; rewrite /snd /=; auto => &hr />.
    by rewrite dt_ll => /> *; algebra.
  qed.

  (* (2) Special soundness - the EXTRACTOR extracts the right witness => knowledge soundness *)
  lemma schnorr_special_soundness (h: statement) msg (ch ch' r r' : exp) &m:
    ch <> ch' =>
    g ^ r  = msg*(h ^ ch ) =>
    g ^ r' = msg*(h ^ ch') =>
    Pr[SpecialSoundnessExperiment(SchnorrPK, SchnorrPKAlgorithms).main(h, msg, ch, r, ch', r') @ &m : (res <> None /\ R h (oget res))] = 1%r.
  proof.
    move => challenges_differ accepting_transcript_1 accepting_transcript_2.
    byphoare (_: h = x /\ msg = m /\ ch = e /\ ch' = e' /\ r = z /\ r' = z' ==> _) => //.
    proc; simplify; inline*.
    auto; rewrite /R /R_DL /oget => &hr /> hne 2!-> /=.
    rewrite expM !expB accepting_transcript_1 accepting_transcript_2.
    rewrite invM (mulcC m{hr}) -mulcA (mulcA m{hr}) mulcV mulcA mulc1 -expB -expM.
    by rewrite ZPF.divrr ?ZPF.subr_eq0 // exp1.
  qed.

  (* (3) SHVZK - the SIMULATOR matches the real distribution => zero knowledge *)
  lemma schnorr_shvzk (D<: SigmaTraceDistinguisher) &m:
    Pr[SimulateHonestVerifier(SchnorrPK, SchnorrPKAlgorithms, D).gameIdeal() @ &m : res] =
    Pr[SimulateHonestVerifier(SchnorrPK, SchnorrPKAlgorithms, D).gameReal() @ &m : res].
  proof.
    byequiv => //.
    proc; inline*.
    seq 27 22: ((glob D){1} = (glob D){2} /\ i{1} = 0 /\ x{1} = h{1} /\ x{2} = h{2} /\
                 to{1} = Some t{2} /\ ={h, w, e}).
    + swap{1} 15 -7; swap{2} 12 -5; swap{1} 11 -3; wp.
      rnd (fun z, z - w{1}*e{1}) (fun r, r + w{1}*e{1}).
      by seq 2 2 : (#pre  /\ ={w0}); auto => />; progress; algebra.
    by call (_:true); rcondf{1} 1; auto.
  qed.
  (* => NIPoK is a Σ-protocol: completeness + special soundness + SHVZK (PROVED). *)
end section SchnorrPKSecurity.

print schnorr_completeness.
print schnorr_special_soundness.
print schnorr_shvzk.

(* ============================================================================ *)
(*  LAYER 3+ - FIAT-SHAMIR => EUF-CMA <= DL (Forking Lemma)                       *)
(*                                                                               *)
(*  General FS theorem (Pointcheval-Stern / Bellare-Neven): a Σ-protocol with     *)
(*    (special soundness ∧ SHVZK) - PROVED ABOVE - under Fiat-Shamir               *)
(*    (`test` replaced by e = H(statement‖message‖ctx), H a random oracle) yields  *)
(*    a signature/NIZK that is EUF-CMA in the ROM, with:                          *)
(*        Adv^{EUF-CMA}_A  ≤  (q_H + q_S(q_S+q_H))/ℓ  +  sqrt( q_H · Adv^{DL}_B )    *)
(*    (the bound printed in the paper; q_H random-oracle queries, q_S signing      *)
(*    queries, ℓ the group order),                                                *)
(*    where: SHVZK => signatures simulated without x (answers the oracle queries); *)
(*           special soundness + forking (RO rewinding) => x extracted => DL solved. *)
(*                                                                               *)
(*  The forking part is computational rewinding. It is NOT developed in this file; *)
(*    it could be built on the standard library (crypto/DigitalSignaturesROM.eca,  *)
(*    crypto/PROM.ec and a forking lemma). The two results proved above (special   *)
(*    soundness, SHVZK) are the two properties of the protocol that it uses.       *)
(*                                                                               *)
(*  Chain of the verification framework, with its two links that are not          *)
(*  mechanized (the Fiat-Shamir reduction above, and the replacement of the       *)
(*  uniform nonce by the deterministic nonce of the implementation):             *)
(*     ProVerif (symbolic, end to end)  <-  CryptoVerif (authentication step,     *)
(*       bound in Psign)  <-  [paper, not mechanized] Psign = Adv^{EUF-CMA} <= DL  *)
(*       <-  EasyCrypt (this file): special soundness + SHVZK of the Σ-protocol.  *)
(* ============================================================================ *)
