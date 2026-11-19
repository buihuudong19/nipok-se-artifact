#!/usr/bin/env python3
"""Second independent check of the NIPoK-SE test vectors with libsodium (PyNaCl).

Point arithmetic and key validation come from libsodium (crypto_scalarmult_ed25519_*_noclamp, crypto_core_ed25519_add,
crypto_core_ed25519_is_valid_point); hashing, decoding and the canonical-s rule are re-implemented here from the
specification, without the Java code and without nipok_ref.py.
Usage: python3 nipok_nacl_check.py <vectors.json> [--report <out.json>]
Exit 0 iff every vector matches; exit 3 (report status 'skipped') if PyNaCl is not installed.
"""
import base64
import hashlib
import json
import sys

L = 2 ** 252 + 27742317777372353535851937790883648493
ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def H(*chunks):
    m = hashlib.sha512()
    for c in chunks:
        m.update(len(c).to_bytes(4, "big"))
        m.update(c)
    return (int.from_bytes(m.digest(), "little") % L).to_bytes(32, "little")


def main(argv):
    path = argv[1]
    report = argv[argv.index("--report") + 1] if "--report" in argv else None
    try:
        import nacl
        import nacl.bindings as b
    except ImportError:
        rep = {"tool": "nipok_nacl_check.py 1.1", "status": "skipped", "reason": "PyNaCl not installed"}
        if report:
            json.dump(rep, open(report, "w", encoding="utf-8"), indent=1)
        print("PyNaCl not installed: libsodium check skipped")
        return 3

    def lib_eq(X, V, s, e):
        try:
            return b.crypto_core_ed25519_add(b.crypto_scalarmult_ed25519_base_noclamp(s),
                                             b.crypto_scalarmult_ed25519_noclamp(e, X)) == V
        except Exception:
            return False

    def decode(blob):
        if any(ch not in ALPHABET for ch in blob) or len(blob) % 4 == 1:
            return None, "decode_encoding"
        raw = base64.urlsafe_b64decode(blob + "=" * (-len(blob) % 4))
        return (raw, None) if len(raw) == 96 else (None, "decode_length")

    def verify(X, V, s, n, idp, cb, idv):
        if len(s) != 32 or int.from_bytes(s, "little") >= L:
            return False, "noncanonical_s"
        e = H(B, V, X, idp, n, cb, idv)
        return (True, None) if lib_eq(X, V, s, e) else (False, "equation")

    def utf8(t, k):
        return bytes.fromhex(t[k + "_utf8"]) if k + "_utf8" in t else t[k].encode("utf-8")

    d = json.load(open(path, encoding="utf-8"))
    B = bytes.fromhex(d["basepoint"])
    by_id = {t["id"]: t for t in d["valid"]}
    rows = []
    for t in d["valid"]:
        x, X, n, cb, V, s = (bytes.fromhex(t[k]) for k in ("x", "X", "N", "cb", "V", "s"))
        idp, idv = utf8(t, "id_P"), utf8(t, "id_V")
        kv = H(b"NIPoK-nonce-key-v1", x)
        v = H(b"NIPoK-nonce-v1", kv, X, idp, n, cb, idv)
        e = H(B, V, X, idp, n, cb, idv)
        s2 = ((int.from_bytes(v, "little") - int.from_bytes(e, "little") * int.from_bytes(x, "little")) % L).to_bytes(
            32, "little")
        checks = {"X": b.crypto_scalarmult_ed25519_base_noclamp(x) == X, "kappa_v": kv.hex() == t["kappa_v"],
                  "v": v.hex() == t["v"], "V": b.crypto_scalarmult_ed25519_base_noclamp(v) == V,
                  "e": e.hex() == t["e"], "s": s2 == s,
                  "blob": base64.urlsafe_b64encode(n + V + s).rstrip(b"=").decode() == t["blob"]}
        raw, st = decode(t["blob"])
        ok = raw is not None and verify(X, raw[32:64], raw[64:96], raw[:32], idp, cb, idv)[0]
        checks["verify"] = ok
        rows.append({"id": t["id"], "category": t.get("category"), "expected": "accept",
                     "result": "accept" if ok else "reject", "match": all(checks.values()), "detail": checks})
    for t in d["invalid"]:
        base = by_id.get(t.get("base"), {})
        ctx = {k: t.get(k, base.get(k)) for k in ("X", "cb")}
        X, cb = bytes.fromhex(ctx["X"]), bytes.fromhex(ctx["cb"])
        idp = utf8(t, "id_P") if "id_P" in t else utf8(base, "id_P")
        idv = utf8(t, "id_V") if "id_V" in t else utf8(base, "id_V")
        detail = {}
        if "blob" in t:
            raw, st = decode(t["blob"])
            ok = False
            if raw is not None:
                ok, st = verify(X, raw[32:64], raw[64:96], raw[:32], idp, cb, idv)
        else:
            ok, st = verify(X, bytes.fromhex(t["V"]), bytes.fromhex(t["s"]), bytes.fromhex(t["N"]), idp, cb, idv)
        match = (not ok) and (t.get("stage") is None or t["stage"] == st)
        if all(k in t for k in ("V", "s", "N")) and "equation_alone" in t:
            V, s, n = bytes.fromhex(t["V"]), bytes.fromhex(t["s"]), bytes.fromhex(t["N"])
            eq = "holds" if lib_eq(X, V, s, H(B, V, X, idp, n, cb, idv)) else "fails"
            want = t.get("equation_alone_libsodium", t["equation_alone"])
            detail["equation_alone_libsodium"] = eq
            match = match and eq == want
        rows.append({"id": t["id"], "category": t.get("category"), "expected": "reject",
                     "result": "accept" if ok else "reject", "stage": st, "match": match, "detail": detail})
    for t in d["enrollment_keys"]:
        X = bytes.fromhex(t["X"])
        acc = len(X) == 32 and b.crypto_core_ed25519_is_valid_point(X)
        res = "accept" if acc else "reject"
        rows.append({"id": t["id"], "category": "key_registration", "expected": t["expected"], "result": res,
                     "match": res == t["expected"]})
    bad = sum(1 for r in rows if not r["match"])
    rep = {"tool": "nipok_nacl_check.py 1.1", "status": "ok", "pynacl": nacl.__version__,
           "libsodium": "bundled with PyNaCl" if hasattr(b, "crypto_core_ed25519_is_valid_point") else "?",
           "python": sys.version.split()[0], "vectors_name": d.get("name"), "total": len(rows),
           "matching": len(rows) - bad, "mismatching": bad, "results": rows}
    if report:
        json.dump(rep, open(report, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    for r in rows:
        if not r["match"]:
            print("  MISMATCH", r)
    print("%s (PyNaCl %s): %d vectors, %d matching, %d mismatching" % (rep["tool"], rep["pynacl"], rep["total"],
                                                                       rep["matching"], bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
