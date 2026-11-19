#!/usr/bin/env python3
"""
impl_info.py - Legend of the Ed25519 implementations (impl) and of the measured operations.
Shared by make_table.py / slim_results.py / plot.py so that tables and charts
carry an explicit description (what Tink is, what jca is, native or pure Java...).
"""

# impl id -> (display name, one-line description)
IMPL_INFO = {
    "jca-sunec": (
        "JCA / SunEC",
        "Ed25519 built into the JDK (SunEC provider), pure Java - baseline; the jca-sunec strategy of the auth-server."),
    "bc-lightweight": (
        "BouncyCastle (lightweight)",
        "Lightweight BouncyCastle API (Ed25519Signer), pure Java - the fastest BC variant (no JCA framework)."),
    "bc-jca": (
        "BouncyCastle (JCA)",
        "BouncyCastle through the JCA framework (java.security.Signature), pure Java - adds the JCA framework overhead."),
    "tink": (
        "Google Tink (subtle)",
        "Tink Ed25519Sign/Verify (subtle package), pure-Java port of ref10 - bypasses the keyset to measure the pure crypto."),
    "libsodium-lazysodium-jna": (
        "libsodium / JNA",
        "libsodium (C, optimised) called through Lazysodium + JNA - HIGH FFI overhead (represents the older integration style)."),
    "libsodium-panama-ffm": (
        "libsodium / Panama FFM",
        "libsodium (C, optimised) called through Foreign Function & Memory (JDK 22+) - LOW FFI overhead, close to native."),
    "conscrypt-boringssl": (
        "Conscrypt / BoringSSL",
        "BoringSSL (C, by Google) through Conscrypt JCA - native; EXACTLY the engine used by Envoy for TLS."),
}

# Classification for colours / notes in the report
IMPL_KIND = {
    "jca-sunec":                 "pure-Java",
    "bc-lightweight":            "pure-Java",
    "bc-jca":                    "pure-Java",
    "tink":                      "pure-Java",
    "libsodium-lazysodium-jna":  "native (JNA)",
    "libsodium-panama-ffm":      "native (FFM)",
    "conscrypt-boringssl":       "native (JCA)",
}

# Preferred display order (pure Java first, native after)
IMPL_ORDER = [
    "jca-sunec", "bc-lightweight", "bc-jca", "tink",
    "libsodium-lazysodium-jna", "libsodium-panama-ffm", "conscrypt-boringssl",
]

OP_INFO = {
    "keygen": "Ed25519 key-pair generation (KeyGen).",
    "sign":   "Signing of one message (Sign).",
    "verify": "Verification of one signature (Verify).",
}


def name(impl):
    return IMPL_INFO.get(impl, (impl, ""))[0]


def desc(impl):
    return IMPL_INFO.get(impl, (impl, ""))[1]


def kind(impl):
    return IMPL_KIND.get(impl, "")


def order_index(impl):
    return IMPL_ORDER.index(impl) if impl in IMPL_ORDER else len(IMPL_ORDER)
