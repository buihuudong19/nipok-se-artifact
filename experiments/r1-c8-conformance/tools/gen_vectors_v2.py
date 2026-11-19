#!/usr/bin/env python3
"""Build nipok-test-vectors-v2.json from nipok-test-vectors-v1.json.

Every v1 vector is kept with identical values; v2 adds a category and a normalized rejection stage to each vector,
the wire blob and the explicit context to every invalid vector, 1 valid vector, 18 invalid vectors and 4 keys,
and describes the stateful cases and the deployment rules that cannot be static vectors. New values are computed
with nipok_ref.py (pure Python); they are checked independently with PyNaCl/libsodium and with the Java code.
Usage: python3 gen_vectors_v2.py <nipok-test-vectors-v1.json> <out-v2.json>
"""
import base64
import hashlib
import json
import os
import sys
import unicodedata

sys.dont_write_bytecode = True        # no __pycache__ next to nipok_ref.py
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))
import nipok_ref as R  # noqa: E402

src, out = sys.argv[1], sys.argv[2]
v1 = json.load(open(src, encoding="utf-8"))
TV = {t["id"]: t for t in v1["valid"]}


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def sha256(label):
    return hashlib.sha256(label.encode()).digest()


def ctx(t):
    return {"X": t["X"], "id_P": t["id_P"], "N": t["N"], "cb": t["cb"], "id_V": t["id_V"]}


def proof_of(t):
    return bytes.fromhex(t["N"]), bytes.fromhex(t["V"]), bytes.fromhex(t["s"])


def eq_alone(X, V, s, n, idp, cb, idv):
    e = R.s32(R.challenge(V, X, idp, n, cb, idv))
    return "holds" if R.equation(X, V, s, e) else "fails"


CAT_V1 = {"IV01": "invalid_proof", "IV02": "invalid_proof", "IV03": "invalid_proof", "IV04": "invalid_proof",
          "IV05": "invalid_proof", "IV06": "mismatched_identity", "IV07": "cross_endpoint_forwarding",
          "IV08": "altered_channel_binding", "IV09": "altered_channel_binding", "IV10": "replayed_nonce",
          "IV11": "mismatched_identity", "IV12": "malformed_context", "IV13": "malformed_context"}
STAGE_V1 = {"length": "decode_length", "noncanonical_s": "noncanonical_s", "equation": "equation"}

# ---- valid: v1 vectors (checked to reproduce), plus TV4 (bank A of the two-bank vectors) -------------------------
valid = []
for t in v1["valid"]:
    g = R.prove(int.from_bytes(bytes.fromhex(t["x"]), "little"), t["id_P"].encode(), bytes.fromhex(t["N"]),
                bytes.fromhex(t["cb"]), t["id_V"].encode())
    assert all(g[k].hex() == t[k] for k in ("X", "kappa_v", "v", "V", "e", "s")), t["id"]
    valid.append(dict(t, category="generation_verification"))

BANK_A = {"id_V": "https://as.bank-a.example", "cb": sha256("NIPoK-SE v2 example certificate of the gateway of bank A"),
          "N": sha256("NIPoK-SE v2 nonce issued by bank A")}
BANK_B = {"id_V": "https://as.bank-b.example", "cb": sha256("NIPoK-SE v2 example certificate of the gateway of bank B"),
          "N": sha256("NIPoK-SE v2 nonce issued by bank B")}
x4 = int.from_bytes(hashlib.sha512(b"NIPoK-SE v2 TV4 witness (example only)").digest(), "little") % R.L
g4 = R.prove(x4, b"alice", BANK_A["N"], BANK_A["cb"], BANK_A["id_V"].encode())
TV4 = {"id": "TV4", "x": R.s32(x4).hex(), "X": g4["X"].hex(), "id_P": "alice", "id_P_utf8": b"alice".hex(),
       "N": BANK_A["N"].hex(), "cb": BANK_A["cb"].hex(), "id_V": BANK_A["id_V"], "kappa_v": g4["kappa_v"].hex(),
       "v": g4["v"].hex(), "V": g4["V"].hex(), "e": g4["e"].hex(), "s": g4["s"].hex(),
       "blob": b64(BANK_A["N"] + g4["V"] + g4["s"]), "expected": "accept", "category": "generation_verification",
       "case": "bank A of the two-bank vectors: issuer URL as id_V, 32-byte cb, own key",
       "inputs_derivation": {"x": "SHA-512('NIPoK-SE v2 TV4 witness (example only)') read little-endian, mod l",
                             "N": "SHA-256('NIPoK-SE v2 nonce issued by bank A')",
                             "cb": "SHA-256('NIPoK-SE v2 example certificate of the gateway of bank A')"}}
valid.append(TV4)

# ---- invalid: v1 vectors with category, stage, explicit context and blob ----------------------------------------
invalid = []
for t in v1["invalid"]:
    base = TV[t["base"]]
    u = dict(t)
    for k in ("X", "id_P", "cb", "id_V"):
        u.setdefault(k, base[k])
    u["category"] = CAT_V1[t["id"]]
    rb = t["rejected_by"]
    u["stage"] = "decode_encoding" if rb.startswith("encoding") else STAGE_V1[rb]
    if all(k in t for k in ("N", "V", "s")) and "blob" not in t:
        u["blob"] = b64(bytes.fromhex(t["N"]) + bytes.fromhex(t["V"]) + bytes.fromhex(t["s"]))
    invalid.append(u)
# IV05: the first rule that rejects V/s swapped is the canonical-s rule (bytes of V read as a scalar exceed l), as
# the authorization server reports (nipok_noncanonical_response); v1 labeled it 'equation'. Outcome unchanged.
for u in invalid:
    if u["id"] == "IV05":
        u["stage"] = "noncanonical_s"
        u["note"] = ("v1 labeled rejected_by 'equation'; the decoding rule rejects it first, because the bytes of V "
                     "read as a scalar exceed l; the outcome (reject) and equation_alone (fails) are unchanged")


def add(vid, cat, case, base_id, X, idp, n, cb, idv, V, s, stage, extra=None, blob=None, fields=True):
    u = {"id": vid, "base": base_id, "case": case, "category": cat, "X": X.hex(), "id_P": idp.decode("utf-8"),
         "cb": cb.hex(), "id_V": idv.decode("utf-8"), "expected": "reject", "stage": stage}
    if fields:
        u.update({"N": n.hex(), "V": V.hex(), "s": s.hex(),
                  "equation_alone": eq_alone(X, V, s, n, idp, cb, idv),
                  "blob": b64(n + V + s)})
    if blob is not None:
        u["blob"] = blob
    if extra:
        u.update(extra)
    ok, st = (R.verify_blob(X, u["blob"], idp, cb, idv) if "blob" in u else R.verify_fields(X, V, s, n, idp, cb, idv))
    assert not ok and st == stage, (vid, ok, st, stage)
    invalid.append(u)


t1, t2, t3 = TV["TV1"], TV["TV2"], TV["TV3"]
X1, n1, V1, s1 = bytes.fromhex(t1["X"]), *proof_of(t1)
cb1, idp1, idv1 = bytes.fromhex(t1["cb"]), t1["id_P"].encode(), t1["id_V"].encode()
s1i = int.from_bytes(s1, "little")
blob1 = t1["blob"]

add("IV14", "invalid_proof", "s replaced by l - s (canonical, wrong value)", "TV1", X1, idp1, n1, cb1, idv1, V1,
    R.s32((R.L - s1i) % R.L), "equation")
s15 = s1i + 15 * R.L
assert s15 < 2 ** 256
add("IV15", "invalid_proof", "s replaced by s + 15l (largest multiple that fits in 32 bytes; bit 255 set)", "TV1",
    X1, idp1, n1, cb1, idv1, V1, s15.to_bytes(32, "little"), "noncanonical_s",
    extra={"equation_alone_libsodium": "fails",
           "note": "with s reduced mod l (elisabeth) the equation alone holds; libsodium ignores bit 255 of a scalar, "
                   "so the equation alone fails there: without the canonical-s rule the two backends disagree"})
add("IV16", "invalid_proof", "V = identity encoding and s = 0", "TV1", X1, idp1, n1, cb1, idv1,
    bytes.fromhex("01" + "00" * 31), bytes(32), "equation")
Vneg = bytearray(V1)
Vneg[31] ^= 0x80
add("IV17", "invalid_proof", "sign bit of V flipped (the point -V)", "TV1", X1, idp1, n1, cb1, idv1, bytes(Vneg), s1,
    "equation")
raw1 = n1 + V1 + s1
add("IV18", "malformed_context", "malformed blob: 97 bytes (one zero byte appended)", "TV1", X1, idp1, n1, cb1, idv1,
    V1, s1, "decode_length", blob=b64(raw1 + b"\x00"), fields=False)
add("IV19", "malformed_context", "malformed blob: empty string", "TV1", X1, idp1, n1, cb1, idv1, V1, s1,
    "decode_length", blob="", fields=False)
add("IV20", "malformed_context", "malformed blob: valid blob followed by '=='", "TV1", X1, idp1, n1, cb1, idv1, V1, s1,
    "decode_encoding", blob=blob1 + "==", fields=False)
add("IV21", "malformed_context", "malformed blob: line feed inserted after 64 characters", "TV1", X1, idp1, n1, cb1,
    idv1, V1, s1, "decode_encoding", blob=blob1[:64] + "\n" + blob1[64:], fields=False)
X3, n3, V3, s3 = bytes.fromhex(t3["X"]), *proof_of(t3)
idp3_nfd = unicodedata.normalize("NFD", t3["id_P"])
assert idp3_nfd != t3["id_P"] and unicodedata.normalize("NFC", t3["id_P"]) == t3["id_P"]
add("IV22", "malformed_context", "id_P in Unicode NFD at the verifier, the proof used NFC (TV3)", "TV3", X3,
    idp3_nfd.encode(), n3, bytes.fromhex(t3["cb"]), t3["id_V"].encode(), V3, s3, "equation",
    extra={"id_P_utf8": idp3_nfd.encode().hex()})
add("IV23", "malformed_context",
    "field boundary moved: cb' = cb || 'b' (33 bytes), id_V' = 'ank'; plain concatenation would be identical", "TV1",
    X1, idp1, n1, cb1 + b"b", b"ank", V1, s1, "equation")
add("IV24", "altered_channel_binding", "verifier cb truncated to 16 bytes", "TV1", X1, idp1, n1, cb1[:16], idv1, V1, s1,
    "equation")
X2, n2, V2, s2 = bytes.fromhex(t2["X"]), *proof_of(t2)
add("IV25", "altered_channel_binding", "proof made with channel binding off (TV2), verifier expects cb", "TV2", X2,
    t2["id_P"].encode(), n2, cb1, t2["id_V"].encode(), V2, s2, "equation")
add("IV26", "mismatched_identity", "id_P = 'ALICE' at the verifier, the proof used 'alice'", "TV1", X1, b"ALICE", n1, cb1,
    idv1, V1, s1, "equation")
x1 = int.from_bytes(bytes.fromhex(t1["x"]), "little")
gw = R.prove(x1, idp1, n1, cb1, idv1, X_in_ctx=X2)
add("IV27", "mismatched_identity", "prover hashed another public key (X of TV2) in place of its own X", "TV1", X1, idp1,
    n1, cb1, idv1, gw["V"], gw["s"], "equation")
X4, n4, V4, s4 = bytes.fromhex(TV4["X"]), *proof_of(TV4)
idvA, idvB = BANK_A["id_V"].encode(), BANK_B["id_V"].encode()
add("IV28", "cross_endpoint_forwarding", "TV4 proof (bank A) forwarded to bank B: id_V and cb of bank B", "TV4", X4,
    b"alice", n4, BANK_B["cb"], idvB, V4, s4, "equation")
add("IV29", "cross_endpoint_forwarding", "TV4 proof checked with the id_V of bank B only (same gateway certificate)",
    "TV4", X4, b"alice", n4, BANK_A["cb"], idvB, V4, s4, "equation")
add("IV30", "cross_endpoint_forwarding", "TV4 proof checked with the cb of bank B only (same id_V)", "TV4", X4, b"alice",
    n4, BANK_B["cb"], idvA, V4, s4, "equation")
gr = R.prove(x4, b"alice", BANK_B["N"], BANK_A["cb"], idvA)
add("IV31", "cross_endpoint_forwarding",
    "relay: agent answers a nonce of bank B while connected to bank A (cb and id_V of A); checked at bank B", "TV4",
    X4, b"alice", BANK_B["N"], BANK_B["cb"], idvB, gr["V"], gr["s"], "equation")

# ---- enrollment keys -----------------------------------------------------------------------------------------------
RULE_V1 = {"KV01": None, "KV02": "key_small_order", "KV03": "key_small_order", "KV04": "key_not_in_subgroup",
           "KV05": "key_noncanonical", "KV06": "key_not_on_curve"}
keys = []
for k in v1["enrollment_keys"]:
    u = dict(k)
    if RULE_V1[k["id"]]:
        u["rule"] = RULE_V1[k["id"]]
    assert R.key_rule(bytes.fromhex(k["X"])) == (RULE_V1[k["id"]] or "accept"), k["id"]
    keys.append(u)
new_keys = [
    ("KV07", "point of order 2 (y = p - 1)", ((R.P - 1)).to_bytes(32, "little").hex(), "key_small_order"),
    ("KV08", "point of order 4 (y = 0)", "00" * 32, "key_small_order"),
    ("KV09", "31 bytes", t1["X"][:62], "key_length"),
    ("KV10", "x = 0 with the sign bit set (non-canonical encoding of the identity)", "01" + "00" * 30 + "80",
     "key_noncanonical"),
]
for kid, case, X, rule in new_keys:
    assert R.key_rule(bytes.fromhex(X)) == rule, kid
    keys.append({"id": kid, "case": case, "X": X, "expected": "reject", "rule": rule})

enc = dict(v1["encoding"])
enc["wire"] = ("blob = base64url without padding (RFC 4648, Sec. 5) of N || V || s, 96 bytes (128 characters); "
               "any character outside the base64url alphabet, including '=', '+', '/' and white space, is rejected")
enc["verify"] = ("decode the blob (alphabet, then |raw| = 96), then s canonical (0 <= s < l), then (stateful) consume N "
                 "in the nonce store, then accept iff compress(s*B + e*X) == V; e as in 'challenge' over the verifier's "
                 "own context (X registered, id_P submitted, N from the blob, cb and id_V configured)")
enc["identity_strings"] = ("id_P and id_V are hashed as their UTF-8 bytes, without Unicode normalization or case "
                           "folding; id_P_utf8 gives the bytes when the text is ambiguous")
stages = {"decode_encoding": "blob not in the base64url alphabet (AS: nipok_bad_encoding)",
          "decode_length": "decoded blob is not 96 bytes (AS: nipok_bad_proof_len)",
          "noncanonical_s": "s >= l (AS: nipok_noncanonical_response)",
          "nonce_store": "N not issued, already consumed or expired (AS: nipok_nonce_invalid; stateful)",
          "equation": "compress(s*B + e*X) != V (AS: nipok_verify_fail)",
          "key_length": "public key is not 32 bytes (registration: HTTP 400 invalid_public_point)",
          "key_noncanonical": "y >= p, or x = 0 with the sign bit set (HTTP 400 invalid_public_point)",
          "key_not_on_curve": "no curve point has this y (HTTP 400 invalid_public_point)",
          "key_small_order": "[8]X = O (HTTP 400 invalid_public_point)",
          "key_not_in_subgroup": "[l]X != O (HTTP 400 invalid_public_point)"}

scenarios = [
    {"id": "SC1", "category": "replayed_nonce", "case": "the same accepted blob submitted a second time",
     "steps": "issue N; submit a valid blob for N (accept); submit the same blob again", "expected": "reject at nonce_store",
     "harness": ["D1a", "D1b"]},
    {"id": "SC2", "category": "replayed_nonce", "case": "a fresh, valid proof for a nonce already consumed",
     "steps": "issue N; log in with N; prove again for N and submit", "expected": "reject at nonce_store",
     "harness": ["D2"]},
    {"id": "SC3", "category": "replayed_nonce", "case": "a failed attempt consumes the nonce",
     "steps": "issue N; submit an invalid proof for N (reject); submit a valid proof for N", "expected": "reject at nonce_store",
     "harness": ["D3a", "D3b"]},
    {"id": "SC4", "category": "replayed_nonce", "case": "nonce never issued by the verifier",
     "steps": "draw 32 random bytes as N; prove and submit", "expected": "reject at nonce_store", "harness": ["C13"]},
    {"id": "SC5", "category": "replayed_nonce", "case": "nonce used after its TTL",
     "steps": "issue N; wait longer than the TTL (60 s in the prototype); submit a valid proof", "expected":
     "reject at nonce_store", "harness": ["D4"]},
    {"id": "SC6", "category": "replayed_nonce", "case": "one valid blob submitted from k sessions at once",
     "steps": "issue N; submit the same valid blob from k sessions concurrently", "expected": "exactly one accept",
     "harness": ["D5"]},
    {"id": "SC7", "category": "replayed_nonce", "case": "nonces issued before a restart of the verifier",
     "steps": "issue N1, N2; consume N1; restart the authorization server; submit valid proofs for N2 and N1",
     "expected": "both reject (in-memory nonce store)", "harness": []},
    {"id": "SC8", "category": "lockout", "case": "lockout after repeated failures (bank policy)",
     "steps": "submit 5 invalid proofs for one user; then a valid one", "expected":
     "reject until the lockout ends (60 s, doubling per further failure, at most 900 s)", "harness": []},
]
rules = [
    {"id": "DR1", "rule": "channel binding on at both ends", "why": "a proof without cb is rejected by a verifier that "
     "expects cb, and a verifier without an expected cb rejects a bound proof (fail closed)", "harness": ["F2", "F3"]},
    {"id": "DR2", "rule": "trust a forwarded cb header only when the gateway overwrites it",
     "why": "with app.psu.nipok.trust-forwarded-cb-header=true and no overwrite, a client chooses cb and a relay passes",
     "harness": ["F4", "F5"]},
    {"id": "DR3", "rule": "a distinct id_V per verifier (the issuer identifier of its authorization server)",
     "why": "with cb off and a shared id_V such as the default 'bank', a proof relayed between two banks is accepted; "
     "distinct id_V values stop it even with cb off", "harness": ["G3", "G4"]},
    {"id": "DR4", "rule": "id_P exchanged byte for byte (NFC recommended for non-ASCII names)",
     "why": "the verifier hashes the submitted bytes; NFC and NFD forms of one name give different challenges",
     "harness": ["C11", "C12"]},
    {"id": "DR5", "rule": "keys checked at registration (canonical, [8]X != O, [l]X == O) and one key per PSU and method",
     "why": "every verifier, whatever its library, then accepts the same set of keys; a second registration returns 409",
     "harness": ["H5", "H6", "R4", "R5", "R8"]},
]
profile = [
    {"parameter": "suite", "value": "edwards25519 prime-order subgroup, SHA-512, 4-byte length prefixes; untagged "
     "challenge; nonce tags NIPoK-nonce-key-v1, NIPoK-nonce-v1", "set_by": "protocol version",
     "if_mismatched": "equation"},
    {"parameter": "wire", "value": "POST /psu/auth, form field password = base64url(N || V || s), 96 bytes",
     "set_by": "protocol version", "if_mismatched": "decode_encoding / decode_length"},
    {"parameter": "N", "value": "32 random bytes in field nipokNonce of GET /psu/login-page; single use; TTL 60 s; "
     "store keyed by N, at most 100000 live nonces", "set_by": "authorization server", "if_mismatched": "nonce_store"},
    {"parameter": "id_V", "value": "app.psu.nipok.verifier-id (prototype: 'bank'); deployment: issuer identifier, "
     "distinct per bank", "set_by": "bank", "if_mismatched": "equation"},
    {"parameter": "cb", "value": "SHA-256 of the DER leaf certificate of the bank gateway (tls-server-end-point); "
     "agent: from its TLS handshake; AS: app.psu.nipok.expected-cb", "set_by": "bank (certificate)",
     "if_mismatched": "equation"},
    {"parameter": "id_P", "value": "UTF-8 bytes of the username registered at the bank", "set_by": "bank account",
     "if_mismatched": "equation"},
    {"parameter": "X", "value": "32-byte canonical point of order l; one per PSU and method at each bank",
     "set_by": "customer agent (wallet)", "if_mismatched": "registration rejected (400)"},
    {"parameter": "registration", "value": "POST /psu/register (username, method=NIPOK, publicKey) with "
     "X-Onboarding-Token; 201, 400, 403, 409", "set_by": "bank onboarding", "if_mismatched": "403 / 400 / 409"},
    {"parameter": "lockout", "value": "5 consecutive failures, then 60 s, doubling per further failure, at most 900 s",
     "set_by": "bank policy", "if_mismatched": "-"},
]
v2 = {
    "name": "NIPoK-SE test vectors v2 (R1-C8)",
    "version": "2",
    "generated_by": "gen_vectors_v2.py 1.1 with nipok_ref.py 1.1 (pure Python); v1 values unchanged",
    "changes_from_v1": [
        "category and normalized rejection stage for every vector; explicit context and wire blob for every invalid "
        "vector; rule for every rejected key",
        "IV05 stage corrected to noncanonical_s (v1 label 'equation'); outcome unchanged",
        "new: TV4; IV14-IV31 (invalid proofs, malformed blobs and contexts, identities, channel bindings, forwarding "
        "between two banks); KV07-KV10; stateful scenarios SC1-SC8; deployment rules DR1-DR5; parameter profile"],
    "encoding": enc,
    "stages": stages,
    "basepoint": v1["basepoint"],
    "valid": valid,
    "invalid": invalid,
    "enrollment_keys": keys,
    "scenarios": scenarios,
    "deployment_rules": rules,
    "profile": profile,
    "two_bank_inputs": {"bank_A": {"id_V": BANK_A["id_V"], "cb": BANK_A["cb"].hex(), "N": BANK_A["N"].hex()},
                        "bank_B": {"id_V": BANK_B["id_V"], "cb": BANK_B["cb"].hex(), "N": BANK_B["N"].hex()},
                        "derivation": "cb = SHA-256('NIPoK-SE v2 example certificate of the gateway of bank A|B'), "
                                      "N = SHA-256('NIPoK-SE v2 nonce issued by bank A|B')"},
}
with open(out, "w", encoding="utf-8") as f:
    json.dump(v2, f, ensure_ascii=False, indent=1)
    f.write("\n")
print("valid %d, invalid %d, keys %d, scenarios %d, rules %d" % (len(valid), len(invalid), len(keys), len(scenarios),
                                                                 len(rules)))
