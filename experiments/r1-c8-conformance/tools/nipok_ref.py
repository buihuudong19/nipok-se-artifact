#!/usr/bin/env python3
"""NIPoK-SE reference implementation used to check the test vectors (Reviewer 1, Comment 8).

Pure Python 3, standard library only, written from the specification and independent of the Java code of the
prototype:
  - edwards25519 arithmetic as in RFC 8032, Sec. 5.1; point decoding is strict (y < p, and x = 0 with the sign
    bit set is rejected, RFC 8032 Sec. 5.1.3 step 4);
  - hash, challenge, deterministic nonce, wire format and key rules as in the "encoding" section of
    nipok-test-vectors-v2.json, which restates Sec. 3 and Algorithms 2-3 of the paper.

Usage:
  python3 nipok_ref.py check <vectors.json> [--report <out.json>]   recompute and check every vector;
                                                                      exit 0 iff every vector matches
  python3 nipok_ref.py selftest                                      curve arithmetic against RFC 8032, Sec. 7.1

Not constant time: for test vectors only, never for secret keys in production.
"""
import base64
import hashlib
import json
import sys

VERSION = "1.1"
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
IDENT = (0, 1, 1, 0)
TAG_KAPPA = b"NIPoK-nonce-key-v1"
TAG_V = b"NIPoK-nonce-v1"
B64URL = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _inv(z):
    return pow(z, P - 2, P)


def point_add(p1, p2):
    """Extended twisted Edwards coordinates (X, Y, Z, T), a = -1 (RFC 8032, Sec. 5.1.4)."""
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * D * t1 * t2 % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def point_mul(k, pt):
    q = IDENT
    while k > 0:
        if k & 1:
            q = point_add(q, pt)
        pt = point_add(pt, pt)
        k >>= 1
    return q


def point_equal(p1, p2):
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def _recover_x(y, sign):
    """x from y and the sign bit; None if y >= p, if no point has this y, or if x = 0 with sign 1."""
    if y >= P:
        return None
    x2 = (y * y - 1) * _inv(D * y * y + 1) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


def compress(pt):
    x, y, z, _ = pt
    zi = _inv(z)
    x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def decompress(b):
    """Strict decoding (RFC 8032, Sec. 5.1.3); None if the 32 bytes do not encode a point canonically."""
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


_GY = 4 * _inv(5) % P
_GX = _recover_x(_GY, 0)
BASE = (_GX, _GY, 1, _GX * _GY % P)
B_ENC = compress(BASE)


def H(*chunks):
    """SHA-512 over fields, each preceded by its 4-byte big-endian length; digest read little-endian, mod l."""
    m = hashlib.sha512()
    for c in chunks:
        m.update(len(c).to_bytes(4, "big"))
        m.update(c)
    return int.from_bytes(m.digest(), "little") % L


def s32(n):
    return n.to_bytes(32, "little")


def challenge(V, X, idp, n, cb, idv):
    """e = H(B, V, X, utf8(id_P), N, cb, utf8(id_V)); cb is the empty string when channel binding is off."""
    return H(B_ENC, V, X, idp, n, cb, idv)


def prove(x, idp, n, cb, idv, X_in_ctx=None):
    """Proof generation with the deterministic nonce (Algorithm 2). X_in_ctx overrides the X of the context
    (used only to build the vector in which the prover hashes another public key)."""
    X = compress(point_mul(x, BASE))
    Xc = X if X_in_ctx is None else X_in_ctx
    kappa = H(TAG_KAPPA, s32(x))
    v = H(TAG_V, s32(kappa), Xc, idp, n, cb, idv)
    V = compress(point_mul(v, BASE))
    e = challenge(V, Xc, idp, n, cb, idv)
    s = (v - e * x) % L
    return {"X": X, "kappa_v": s32(kappa), "v": s32(v), "V": V, "e": s32(e), "s": s32(s)}


def equation(X, V, s, e):
    """compress([s]B + [e]X) == V with s reduced mod l (the decoding rule is checked separately)."""
    px = decompress(X)
    if px is None:
        return False
    r = point_add(point_mul(int.from_bytes(s, "little") % L, BASE), point_mul(int.from_bytes(e, "little"), px))
    return compress(r) == V


def decode_blob(blob):
    """Wire format: base64url without padding (RFC 4648, Sec. 5) of N || V || s, 96 bytes.
    Returns (raw, stage); stage is None when decoding succeeded."""
    try:
        raw = blob.encode("ascii")
    except UnicodeEncodeError:
        return None, "decode_encoding"
    if any(c not in B64URL for c in raw) or len(raw) % 4 == 1:
        return None, "decode_encoding"
    data = base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))
    if len(data) != 96:
        return None, "decode_length"
    return data, None


def verify_fields(X, V, s, n, idp, cb, idv):
    """Algorithm 3 without the nonce store: canonical s (0 <= s < l), then the verification equation."""
    if len(s) != 32 or int.from_bytes(s, "little") >= L:
        return False, "noncanonical_s"
    e = s32(challenge(V, X, idp, n, cb, idv))
    return (True, None) if equation(X, V, s, e) else (False, "equation")


def verify_blob(X, blob, idp, cb, idv):
    raw, stage = decode_blob(blob)
    if raw is None:
        return False, stage
    return verify_fields(X, raw[32:64], raw[64:96], raw[0:32], idp, cb, idv)


def key_rule(Xb):
    """Registration rule for X: 32 bytes, canonical encoding, on the curve, [8]X != O, [l]X == O."""
    if len(Xb) != 32:
        return "key_length"
    y = int.from_bytes(Xb, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= P:
        return "key_noncanonical"
    x2 = (y * y - 1) * _inv(D * y * y + 1) % P
    if x2 == 0 and sign == 1:
        return "key_noncanonical"
    x = _recover_x(y, sign)
    if x is None:
        return "key_not_on_curve"
    pt = (x, y, 1, x * y % P)
    if point_equal(point_mul(8, pt), IDENT):
        return "key_small_order"
    if not point_equal(point_mul(L, pt), IDENT):
        return "key_not_in_subgroup"
    return "accept"


def _hx(t, k):
    return bytes.fromhex(t[k])


def _u8(t, k):
    return t[k].encode("utf-8")


def check(path, report_path=None):
    d = json.load(open(path, encoding="utf-8"))
    rows = []
    for t in d["valid"]:
        x = int.from_bytes(_hx(t, "x"), "little")
        idp, idv, n, cb = _u8(t, "id_P"), _u8(t, "id_V"), _hx(t, "N"), _hx(t, "cb")
        g = prove(x, idp, n, cb, idv)
        blob = base64.urlsafe_b64encode(n + g["V"] + g["s"]).rstrip(b"=").decode()
        fields = {k: g[k].hex() == t[k] for k in ("X", "kappa_v", "v", "V", "e", "s")}
        fields["blob"] = blob == t["blob"]
        ok, stage = verify_blob(g["X"], t["blob"], idp, cb, idv)
        fields["verify"] = ok
        rows.append({"id": t["id"], "category": t.get("category", "generation_verification"), "expected": "accept",
                     "result": "accept" if ok else "reject", "stage": stage,
                     "match": all(fields.values()), "detail": fields})
    valid_by_id = {t["id"]: t for t in d["valid"]}
    for t in d["invalid"]:
        base = valid_by_id.get(t.get("base"), {})
        if any(k not in t for k in ("X", "id_P", "cb", "id_V")):   # v1 blob vectors: context of the base vector
            t = dict(t, **{k: base[k] for k in ("X", "id_P", "cb", "id_V") if k not in t})
        X, idp, idv, cb = _hx(t, "X"), _u8(t, "id_P"), _u8(t, "id_V"), _hx(t, "cb")
        detail = {}
        if "blob" in t:
            ok, stage = verify_blob(X, t["blob"], idp, cb, idv)
        else:
            ok, stage = verify_fields(X, _hx(t, "V"), _hx(t, "s"), _hx(t, "N"), idp, cb, idv)
        want_stage = t.get("stage")
        match = (not ok) and (want_stage is None or want_stage == stage)
        if all(k in t for k in ("V", "s", "N")) and "equation_alone" in t:
            e = s32(challenge(_hx(t, "V"), X, idp, _hx(t, "N"), cb, idv))
            eq = equation(X, _hx(t, "V"), _hx(t, "s"), e)
            detail["equation_alone"] = "holds" if eq else "fails"
            match = match and detail["equation_alone"] == t["equation_alone"]
        if "blob" in t and all(k in t for k in ("V", "s", "N")):
            raw, _ = decode_blob(t["blob"])
            if raw is not None:
                same = raw == _hx(t, "N") + _hx(t, "V") + _hx(t, "s")
                detail["blob_equals_fields"] = same
                match = match and same
        rows.append({"id": t["id"], "category": t.get("category"), "expected": "reject",
                     "result": "accept" if ok else "reject", "stage": stage, "expected_stage": want_stage,
                     "match": match, "detail": detail})
    for t in d["enrollment_keys"]:
        rule = key_rule(_hx(t, "X"))
        want = t["expected"]
        res = "accept" if rule == "accept" else "reject"
        match = res == want and (t.get("rule") is None or t["rule"] == rule)
        rows.append({"id": t["id"], "category": "key_registration", "expected": want, "result": res,
                     "stage": None if rule == "accept" else rule, "expected_stage": t.get("rule"), "match": match})
    n_bad = sum(1 for r in rows if not r["match"])
    rep = {"tool": "nipok_ref.py " + VERSION + " (pure Python, standard library only)",
           "python": sys.version.split()[0], "vectors_file": path, "vectors_name": d.get("name"),
           "total": len(rows), "matching": len(rows) - n_bad, "mismatching": n_bad, "results": rows}
    if report_path:
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(rep, f, ensure_ascii=False, indent=1)
    return rep


def selftest():
    # RFC 8032, Sec. 7.1, TEST 1: public key of the given secret key (exercises decoding, scalar
    # multiplication and encoding of this module).
    sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    h = hashlib.sha512(sk).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    pub = compress(point_mul(a, BASE))
    ok = [pub.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"]
    ok.append(B_ENC.hex() == "58" + "66" * 31)
    ok.append(point_equal(point_mul(L, BASE), IDENT))
    ok.append(decompress(pub) is not None and compress(decompress(pub)) == pub)
    return all(ok), ok


def main(argv):
    if len(argv) >= 2 and argv[1] == "selftest":
        ok, parts = selftest()
        print("selftest:", "PASS" if ok else "FAIL", parts)
        return 0 if ok else 1
    if len(argv) >= 3 and argv[1] == "check":
        report = None
        if "--report" in argv:
            report = argv[argv.index("--report") + 1]
        ok, parts = selftest()
        if not ok:
            print("selftest FAIL", parts)
            return 1
        rep = check(argv[2], report)
        for r in rep["results"]:
            print("  %-5s %-26s expected %-6s got %-6s stage %-20s %s" % (
                r["id"], r["category"], r["expected"], r["result"], r["stage"] or "-",
                "ok" if r["match"] else "MISMATCH " + json.dumps(r.get("detail", {}))))
        print("%s: %d vectors, %d matching, %d mismatching" % (rep["tool"], rep["total"], rep["matching"],
                                                               rep["mismatching"]))
        return 0 if rep["mismatching"] == 0 else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
