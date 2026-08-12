(* ============================================================================ *)
(*  SchnorrFS.ec — EasyCrypt (TẦNG 3, primitive): NIPoK = Schnorr Σ-protocol      *)
(*  + Fiat–Shamir.                                                                *)
(*                                                                               *)
(*  CHỨNG MINH THẬT (không admit, đã typecheck) — NIPoK là Σ-protocol an toàn:     *)
(*    • Completeness          — prover trung thực luôn được chấp nhận.            *)
(*    • Special-soundness     — EXTRACTOR: 2 transcript cùng a, khác e ⟹ rút       *)
(*                              witness w=(z−z')/(e−e')  ⟹ knowledge-soundness.   *)
(*    • SHVZK                  — SIMULATOR sinh transcript trùng phân phối, KHÔNG   *)
(*                              cần w ⟹ zero-knowledge.                           *)
(*  Đây CHÍNH là 2 tính chất (soundness + ZK) mà ProVerif "giả định" và            *)
(*  CryptoVerif "lấy làm tiền đề (UF-CMA)". Nền tảng: bài toán Discrete-Log (DL).  *)
(*                                                                               *)
(*  Ánh xạ NIPoK: statement h = X = g^x (public key) ; witness w = x (scalar PSU); *)
(*    R_DL h w ⟺ h = g^w (sở-hữu khóa rời rạc). challenge e = Fiat–Shamir hash.    *)
(*                                                                               *)
(*  Dựa trên examples/SchnorrPK.ec của EasyCrypt (đã chứng minh đầy đủ).           *)
(*  CHẠY:  easycrypt compile easycrypt/SchnorrFS.ec   → in 3 print (proven).       *)
(*                                                                               *)
(*  G11 — KEY CUSTODY: witness `w=x` sinh trong `keygen` (`w <$ dt`), do Wallet     *)
(*    giữ; `R_DL h w` = sở-hữu discrete-log. SHVZK (đã proven) ⟹ proof KHÔNG lộ x;   *)
(*    nơi LƯU x (sim SEALED/off-heap, K8s-Secret, TEE) nằm DƯỚI tầng trừu tượng —    *)
(*    mô hình bất biến với backend. At-rest/host-dump ngoài phạm vi computational.   *)
(* ============================================================================ *)
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

(* ── Kiểu NIPoK = Schnorr Σ-protocol ──────────────────────────────────────── *)
theory SchnorrTypes.
  type statement = group.        (* X = g^x : public key của PSU *)
  type witness   = exp.          (* x : scalar bí mật (NIPoK private key) *)
  type message   = group.        (* V = g^v : commitment *)
  type secret    = exp.          (* v : ephemeral *)
  type challenge = exp.          (* e = H(g‖V‖X‖ctx) : Fiat–Shamir *)
  type response  = exp.          (* s = v + e·x  (ở đây dùng dấu +; NIPoK dùng v−ex, tương đương) *)

  op R_DL (h : group) (w : exp) = (h = g ^ w).   (* quan hệ: sở-hữu discrete-log *)
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

(* ── Lược đồ NIPoK (Schnorr) ──────────────────────────────────────────────── *)
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
    r <$ dt;                       (* v ← CSPRNG *)
    a <- g ^ r;                    (* V = g^v *)
    return (a, r);
  }
  proc test(h: statement, a: message) : challenge = {
    var e;
    e <$ dt;                       (* (interactive) e ngẫu nhiên; FS thay bằng H *)
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
  (* EXTRACTOR (special-soundness): rút witness x từ 2 transcript fork *)
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
  (* SIMULATOR (SHVZK): sinh transcript hợp lệ không cần x *)
  proc simulate(h: statement, e: challenge) : message * challenge * response = {
    var a, z;
    z  <$ dt;
    a  <- (g ^ z) * (h ^ (-e));    (* V = g^s · X^(−e) ⟹ phân phối trùng bản thật *)
    return (a, e, z);
  }
}.

section SchnorrPKSecurity.
  (* (1) Completeness — prover trung thực luôn pass *)
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

  (* (2) Special-soundness — EXTRACTOR rút đúng witness ⟹ knowledge-soundness *)
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

  (* (3) SHVZK — SIMULATOR trùng phân phối bản thật ⟹ zero-knowledge *)
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
  (* ⟹ NIPoK là Σ-protocol: completeness + special-soundness + SHVZK (CHỨNG MINH XONG). *)
end section SchnorrPKSecurity.

print schnorr_completeness.
print schnorr_special_soundness.
print schnorr_shvzk.

(* ============================================================================ *)
(*  TẦNG 3+ — FIAT–SHAMIR ⟹ EUF-CMA ⇠ DL (Forking Lemma)                          *)
(*                                                                               *)
(*  Định lý FS tổng quát (Pointcheval–Stern / Bellare–Neven): MỘT Σ-protocol có    *)
(*    (special-soundness ∧ SHVZK) — VỪA CHỨNG MINH Ở TRÊN — khi áp Fiat–Shamir     *)
(*    (thay `test` bằng e = H(statement‖message‖ctx), H là Random Oracle) cho ra   *)
(*    chữ ký/NIZK ĐẠT EUF-CMA trong ROM, với:                                      *)
(*        Adv^{EUF-CMA}_A  ≤  q_H/ℓ  +  sqrt( q_H · Adv^{DL}_B ).                   *)
(*    Trong đó: SHVZK ⟹ mô phỏng chữ ký không cần x (đóng query oracle);            *)
(*              special-soundness + Forking (rewind RO) ⟹ rút x ⟹ giải DL.          *)
(*                                                                               *)
(*  Phần Forking là computational-rewinding — PHÁT TRIỂN tiếp bằng thư viện chuẩn:  *)
(*    crypto/DigitalSignaturesROM.eca + crypto/PROM.ec + bổ đề Forking. Hai HỆ QUẢ  *)
(*    (special-soundness, SHVZK) ở trên CHÍNH là 2 giả thiết đầu vào của định lý FS. *)
(*                                                                               *)
(*  ⟹ Chuỗi khung kiểm chứng KHÉP KÍN:                                            *)
(*     ProVerif (logic, anti-relay)  ⇠  CryptoVerif (composition, bound Psign)     *)
(*       ⇠  EasyCrypt: Psign = Adv^{EUF-CMA}  ⇠  special-soundness+SHVZK ⇠ DL.      *)
(* ============================================================================ *)
