#!/usr/bin/env python3
"""
impl_info.py — Chú giải các cài đặt (impl) Ed25519 và phép đo.
Dùng chung cho make_table.py / slim_results.py / plot.py để bảng & biểu đồ
có diễn giải cụ thể (Tink là gì, jca là gì, native hay pure-Java...).
"""

# impl id -> (tên hiển thị, mô tả 1 dòng)
IMPL_INFO = {
    "jca-sunec": (
        "JCA / SunEC",
        "Ed25519 dựng sẵn trong JDK (provider SunEC), thuần Java — baseline; ĐÚNG cái auth-server đang dùng."),
    "bc-lightweight": (
        "BouncyCastle (lightweight)",
        "API nhẹ của BouncyCastle (Ed25519Signer), thuần Java — bản BC nhanh nhất (không qua khung JCA)."),
    "bc-jca": (
        "BouncyCastle (JCA)",
        "BouncyCastle qua khung JCA (java.security.Signature), thuần Java — thêm overhead khung JCA."),
    "tink": (
        "Google Tink (subtle)",
        "Tink Ed25519Sign/Verify (gói subtle), port thuần Java của ref10 — bỏ qua keyset để đo crypto thuần."),
    "libsodium-lazysodium-jna": (
        "libsodium / JNA",
        "libsodium (C, tối ưu) gọi qua Lazysodium + JNA — FFI overhead CAO (đại diện cách tích hợp cũ)."),
    "libsodium-panama-ffm": (
        "libsodium / Panama FFM",
        "libsodium (C, tối ưu) gọi qua Foreign Function & Memory (JDK 22+) — FFI overhead THẤP, sát native thật."),
    "conscrypt-boringssl": (
        "Conscrypt / BoringSSL",
        "BoringSSL (C, của Google) qua Conscrypt JCA — native; ĐÚNG engine mà Envoy dùng cho TLS."),
}

# Phân loại để tô màu / ghi chú trong báo cáo
IMPL_KIND = {
    "jca-sunec":                 "pure-Java",
    "bc-lightweight":            "pure-Java",
    "bc-jca":                    "pure-Java",
    "tink":                      "pure-Java",
    "libsodium-lazysodium-jna":  "native (JNA)",
    "libsodium-panama-ffm":      "native (FFM)",
    "conscrypt-boringssl":       "native (JCA)",
}

# Thứ tự hiển thị ưa thích (pure-Java trước, native sau)
IMPL_ORDER = [
    "jca-sunec", "bc-lightweight", "bc-jca", "tink",
    "libsodium-lazysodium-jna", "libsodium-panama-ffm", "conscrypt-boringssl",
]

OP_INFO = {
    "keygen": "Sinh cặp khóa Ed25519 (KeyGen).",
    "sign":   "Ký một thông điệp (Sign).",
    "verify": "Xác minh một chữ ký (Verify).",
}


def name(impl):
    return IMPL_INFO.get(impl, (impl, ""))[0]


def desc(impl):
    return IMPL_INFO.get(impl, (impl, ""))[1]


def kind(impl):
    return IMPL_KIND.get(impl, "")


def order_index(impl):
    return IMPL_ORDER.index(impl) if impl in IMPL_ORDER else len(IMPL_ORDER)
