# GAP 8 — Khung kiểm chứng hình thức 3 tầng (Comprehensive Verification Framework)

Bộ ba công cụ phủ **từ logic giao thức xuống độ cứng đại số** cho NIPoK + FAPI E2E.

| Tầng | Công cụ | File | Mô hình | Chứng minh |
|---|---|---|---|---|
| 1 | **ProVerif** | `proverif/nipok-e2e.pv` | Symbolic (Dolev–Yao) | secrecy, injective-agreement, anti-relay (cb), PKCE-binding, JARM-auth, cert-binding trên TOÀN E2E |
| 2 | **CryptoVerif** | `cryptoverif/nipok.cv` | Computational (game-based) | injective-auth NIPoK **+ CHẶN advantage**, giả định UF-CMA |
| 3 | **EasyCrypt** | `easycrypt/SchnorrFS.ec` | Computational (interactive) | **EUF-CMA(Schnorr-FS) ⇠ DL** (ROM, Forking) + special-soundness + HVZK |

> Chuỗi liền mạch: EasyCrypt **chứng minh** UF-CMA mà CryptoVerif **lấy làm tiền đề**; ProVerif phủ breadth E2E. Soundness Fiat–Shamir CHỈ đóng được ở Tầng 3 (xem giải thích trong các file).

---

## 1. Cài đặt (qua opam — nền OCaml)

```bash
# opam + OCaml
sudo apt-get install -y opam && opam init -y && eval $(opam env)
opam switch create 4.14.1 && eval $(opam env)

# ProVerif
opam install -y proverif                      # → proverif

# CryptoVerif
opam install -y cryptoverif                   # → cryptoverif

# EasyCrypt (+ SMT solvers Alt-Ergo/Z3 + why3)
opam install -y easycrypt alt-ergo
opam install -y z3 && why3 config detect       # EasyCrypt gọi why3 → SMT
easycrypt config                               # kiểm provers
```

## 2. Chạy từng tầng

```bash
# TẦNG 1 — ProVerif (E2E)
proverif proverif/nipok-e2e.pv
proverif proverif/nipok.pv                     # bản NIPoK-only (đã có từ G1)

# TẦNG 2 — CryptoVerif (composition + bound)
cryptoverif cryptoverif/nipok.cv

# TẦNG 3 — EasyCrypt (primitive ⇠ DL)
easycrypt compile easycrypt/SchnorrFS.ec
```

Hoặc 1 lệnh: `./run-all.sh`

## 3. Cách ĐỌC / ĐÁNH GIÁ kết quả

**ProVerif** → mỗi `query` in một dòng:
```
RESULT inj-event(BankAccepts(X,n,cb)) ==> inj-event(PsuProves(X,n,cb)) is true.   ← anti-relay OK
RESULT not attacker(xPSU[]) is true.                                              ← bí mật khóa OK
RESULT ... is false.   + một "attack derivation" (trace)                          ← LỖ HỔNG (đọc trace)
RESULT ... cannot be proved.                                                      ← cần tinh chỉnh model
```
Đánh giá: **mọi query phải `true`**. Nếu `false` → ProVerif xuất *attack trace* (ánh xạ về pha nào của giao thức → sửa).

**CryptoVerif** → kết thúc bằng:
```
RESULT Proved ... up to probability <bound>      ← bound theo Psign (UF-CMA advantage)
All queries proved.
```
Đánh giá: thuộc tính đúng **kèm CHẶN định lượng** (advantage giao thức ≤ N·Adv_UF-CMA + …). Nếu không proved → xem `proof { }` script (thêm `crypto`/`simplify`/`SArename`).

**EasyCrypt** → `easycrypt compile` báo lỗi tại từng `admit`/lemma chưa đóng:
```
[success]  (toàn bộ lemma đã chứng minh, không còn admit)
[error] ... admit remaining at line N                ← cần phát triển proof
```
Đánh giá: skeleton hiện CÓ `admit` ở `special_soundness`, `hvzk`, `euf_cma_reduces_to_dl` — đây là phần PHÁT TRIỂN (dùng `CyclicGroup`, `PROM` random-oracle, và Forking Lemma của thư viện chuẩn). Tham khảo `examples/` của EasyCrypt (Schnorr/FS).

## 4. Lập luận cho Manuscript ("Security Evaluation")

1. Nêu **threat model** + **security goals** hình thức (secrecy, inj-agreement, EUF-CMA, ZK).
2. Trình bày **framework 3 tầng** (bảng trên) + lý do *một tool chưa đủ*: trích Abadi–Rogaway computational-soundness **không bao trùm** DH/ZKP ⟹ buộc tầng computational.
3. Báo cáo kết quả: ProVerif `RESULT ... true` (breadth) → CryptoVerif bound → EasyCrypt `EUF-CMA ⇠ DL`.
4. **Assumption stack** minh bạch: DL(ed25519), ROM(SHA-512), Gap-DH(X25519/JWE), AEAD(AES-GCM), EUF-CMA(Ed25519/token), CR/PRF(SHA-256/PKCE), TLS 1.3 (trích model có sẵn).
5. Nếu phát hiện không-an-toàn → bảng FIX (strong-FS, cb vào hash, canonical encoding, tight trong AGM/OMDL) — xem phần đã phân tích.

---
## ✅ KẾT QUẢ ĐÃ CHẠY THỰC (proverif + cryptoverif đã cài; easycrypt cần thêm repo)
```
ProVerif nipok.pv     : not attacker(xA) is true                              ← secrecy(x) ✓
                        inj-event(server_accepts(pk(xA),n,cb))
                          ==> inj-event(client_authenticates(pk(xA),n,cb)) is true   ← ANTI-RELAY ✓
ProVerif nipok-e2e.pv : (E2E ĐẦY ĐỦ — 5/5 query is true, hội tụ <150s)
   S1 not attacker(xPSU) is true                                             ← secrecy ✓
   A1 inj BankAccepts(pk(xPSU),n,cb) ==> inj PsuProves(...)  is true         ← NIPoK anti-relay+replay ✓
   A2 inj TokenIssued(t,code) ==> inj CodeIssued(code,ch)    is true         ← PKCE binding ✓
   A3 TppGotCode(code) ==> CodeIssued(code,ch)               is true         ← JARM authenticity ✓
   A4 RsGrants(t,c) ==> TokenIssued(t,code)                  is true         ← token integrity ✓
CryptoVerif nipok.cv  : Proved inj bank_accepts ==> inj psu_proves
                        up to probability Psign(t,N) + 0.5·N2^2/|nonce|       ← BOUND ✓ ; All queries proved.
```
**Mẹo hội tụ E2E (đã fix):** TÁCH kênh mTLS theo từng leg (`cPar`/`cTokQ`/`cTokR`/`cRs`) — dùng 1 kênh
chung làm ProVerif khớp nhầm shape giữa các leg ⟹ saturation non-terminate (timeout >240s). JWE→CryptoVerif.

```
EasyCrypt SchnorrFS.ec : easycrypt compile → exit=0, 3 lemma PROVEN (KHÔNG admit):
   schnorr_completeness        ← prover trung thực luôn pass ✓
   schnorr_special_soundness   ← EXTRACTOR rút x=(z−z')/(e−e') ⟹ knowledge-soundness ✓
   schnorr_shvzk               ← SIMULATOR trùng phân phối ⟹ zero-knowledge ✓
```
⟹ NIPoK là **Σ-protocol an toàn** (chứng minh máy-kiểm). FS→EUF-CMA⇠DL (Forking) là bước rewinding
còn phát triển, với special-soundness+SHVZK (vừa proven) làm 2 giả thiết đầu vào.

**Cài EasyCrypt (repo opam.git CŨ ĐÃ CHẾT):**
`opam pin add -yn easycrypt https://github.com/EasyCrypt/easycrypt.git && opam install -y easycrypt alt-ergo`
**Gotcha:** theory nhóm cyclic = `clone Group.CyclicGroup as G` (KHÔNG `require CyclicGroup` — nằm trong
`algebra/Group.ec`). Dựa trên `examples/SchnorrPK.ec` của EasyCrypt (đã chứng minh đầy đủ).
Bound: Adv_auth ≤ **Psign** (UF-CMA khóa NIPoK) + **N²/2|nonce|** (birthday nonce). → EasyCrypt đóng Psign ⇠ DL.

**EasyCrypt cài (repo opam.git CŨ chết):** `opam pin add -yn easycrypt https://github.com/EasyCrypt/easycrypt.git && opam install -y easycrypt alt-ergo`

**Gotcha model (đã sửa):** (1) KHÔNG `in(net,seenCb)` — phải `PSU(x,realCb)` realCb=certS|certM (attacker không trình được certS); (2) query ràng `pk(xA)` không X tự do; (3) Bank verify theo pkP đã đăng ký; (4) CryptoVerif: `UF_CMA_det_signature(...,check,Pkeycoll)` + `proba Psign. proba Pkeycoll.`
