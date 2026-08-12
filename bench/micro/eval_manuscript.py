#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
eval_manuscript.py — Bộ công cụ sinh BẢNG + ĐỒ THỊ chuẩn ấn phẩm Q1 cho phần "Evaluation &
Benchmarking" — 7 cơ chế xác thực PSU. Tách bạch: (A) DATA, (B) TABLES, (C) FIGURES.

DANH PHÁP CHUẨN (NHIỆM VỤ 1):
  NIPoK (Ours)     — Non-Interactive Proof of Knowledge (Schnorr NIZK, RFC 8235)        [HIỆN ĐẠI]
  Schnorr-IZK      — 3-pass Interactive Zero-Knowledge (Schnorr gốc, RFC 8235)          [HIỆN ĐẠI]
  ML-DSA-65        — Module-Lattice DSA hậu lượng tử (FIPS 204)                          [HIỆN ĐẠI]
  Pure-EdDSA       — EdDSA/Ed25519 thuần (RFC 8032)                                      [HIỆN ĐẠI]
  Private-Key-JWT  — JWT client-assertion bất đối xứng (RFC 7523 + RFC 8037 Ed25519)     [TRUYỀN THỐNG]
  mTLS-PSU         — Mutual TLS X.509 cho PSU (RFC 8705 + RFC 8410 Ed25519)              [TRUYỀN THỐNG]
  Password         — Username/Password băm Argon2id (RFC 9106)                           [TRUYỀN THỐNG]

Nguồn số liệu: micro-benchmark JMH backend elisabeth (results/official-final.json); cấu hình đo THẬT
truyền qua env JMH_CONFIG (script đo set) — KHÔNG hardcode metadata lên hình. SUBMISSION=1 = bản nộp
(strip suptitle/variant-tag; thông tin chuyển vào caption). Mỗi hình xuất PNG 300 DPI + PDF vector.
Chạy:  python3 eval_manuscript.py            # xuất tables_*.md + fig1..4 (.png + .pdf)
"""

import json
import os
import warnings

import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import seaborn as sns

# tight_layout + GridSpec/polar phát UserWarning vô hại (đã dùng rect=) — tắt cho output sạch.
warnings.filterwarnings("ignore", message=".*not compatible with tight_layout.*")

# ════════════════════════════════════════════════════════════════════════════════════════
# (A) DATA — tách HOÀN TOÀN khỏi phần vẽ. Nguồn rõ ràng cho từng nhóm trường.
# ════════════════════════════════════════════════════════════════════════════════════════
# OUT_DIR/JSON_PATH override được qua env (shell script đặt kết quả vào thư mục riêng).
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.environ.get("OUT_DIR") or _SCRIPT_DIR
JSON_PATH = os.environ.get("JSON_PATH") or os.path.join(_SCRIPT_DIR, "results", "official-final.json")

# Thứ tự hiển thị: truyền thống → hiện đại → Ours (nhấn cuối). HIGHLIGHT = cơ chế đề xuất.
ORDER = ["Password", "mTLS-PSU", "Private-Key-JWT", "Pure-EdDSA", "Schnorr-IZK", "ML-DSA-65", "NIPoK"]
HIGHLIGHT = "NIPoK"
GROUP = {  # NHIỆM VỤ 1 — phân nhóm (giá trị hiển thị tiếng Anh cho manuscript)
    "Password": "Traditional", "mTLS-PSU": "Traditional", "Private-Key-JWT": "Traditional",
    "Pure-EdDSA": "Modern", "Schnorr-IZK": "Modern", "ML-DSA-65": "Modern", "NIPoK": "Modern (Ours)",
}

# ── (A.1) HẰNG SỐ GIAO THỨC (KHÔNG đo JMH được — sự thật THIẾT KẾ: kích thước byte + tính chất) ──
#   sig/payload/pubkey (byte): chuẩn giao thức. rtt/state/anti-replay/zk/pq/rfc: tính chất giao thức.
#   (genkey KHÔNG ở đây nữa — đã chuyển sang dẫn từ data/gen_R trong load_measured.)
SPEC = {
    "NIPoK":           dict(sig=64,   payload=96,   pubkey=32,
                            rtt=1, state="nonce-store", antireplay="server nonce", zk="✓", pq="✗",
                            rfc="RFC 8235"),
    "Schnorr-IZK":     dict(sig=64,   payload=96,   pubkey=32,
                            rtt=2, state="session-store", antireplay="nonce+session", zk="✓", pq="✗",
                            rfc="RFC 8235 (i)"),
    "ML-DSA-65":       dict(sig=3309, payload=3341, pubkey=1952,
                            rtt=1, state="nonce-store", antireplay="server nonce", zk="✗", pq="✓",
                            rfc="FIPS 204"),
    "Pure-EdDSA":      dict(sig=64,   payload=96,   pubkey=32,
                            rtt=1, state="nonce-store", antireplay="server nonce", zk="✗", pq="✗",
                            rfc="RFC 8032"),
    "Private-Key-JWT": dict(sig=64,   payload=320,  pubkey=32,
                            rtt=1, state="jti-store", antireplay="jti+exp", zk="✗", pq="✗",
                            rfc="RFC 7523/8037"),
    "mTLS-PSU":        dict(sig=64,   payload=480,  pubkey=32,
                            rtt=0, state="stateless", antireplay="TLS nonce", zk="✗", pq="✗",
                            rfc="RFC 8705/8410"),
    "Password":        dict(sig=0,    payload=20,   pubkey=96,
                            rtt=1, state="stateless", antireplay="—", zk="✗", pq="✗",
                            rfc="RFC 9106"),
}

# ── (A.2) SỐ ĐO JMH — LẤY 100% TỪ JSON (official-final.json), KHÔNG hardcode, KHÔNG fallback ───────
#   sign: client prove/sign µs (None = không ký per-auth). alloc: KB/op (gc.alloc.rate.norm).
#   parse_verify: chỉ JWT/mTLS (parse chuỗi + verify). gen_R/compute_s: chỉ Schnorr (2 cấu phần).
# ⚠ KHÔNG còn số đo hardcode. TOÀN BỘ verify/sign/alloc/parse lấy TỪ JSON (load_measured, BẮT BUỘC JSON).
# GenKey KHÔNG được JMH đo (harness per-mechanism không có keygen-benchmark) ⟹ dẫn xuất:
#   • 5 cơ chế EC (NIPoK/Schnorr/EdDSA/JWT/mTLS): keygen = X=xG = 1 fixed-base mult = ĐÚNG gen_R ĐO ĐƯỢC;
#   • ML-DSA / Password: KHÔNG bench keygen ⟹ HẰNG ước lượng (ghi rõ ở Notes) — 2 giá trị cố định DUY NHẤT.
_GENKEY_CONST = {"ML-DSA-65": 60.0, "Password": 0.5}
_EC_GENKEY_MECHS = ["NIPoK", "Schnorr-IZK", "Pure-EdDSA", "Private-Key-JWT", "mTLS-PSU"]

# Map lớp JMH → (mechanism, verify-method, [sign-method(s)], parse-method|None)
JMH_MAP = {
    "NipokBenchmark":         ("NIPoK", "verify_server", ["prove_client"], None),
    "SchnorrBenchmark":       ("Schnorr-IZK", "verify_server", ["gen_R", "compute_s"], None),
    "MlDsaAuthBenchmark":     ("ML-DSA-65", "verify_server", ["sign_client"], None),
    "EdDsaAuthBenchmark":     ("Pure-EdDSA", "verify_server", ["sign_client"], None),
    "PrivateKeyJwtBenchmark": ("Private-Key-JWT", "verify_only", ["sign_client"], "parse_and_verify"),
    "MtlsCertBenchmark":      ("mTLS-PSU", "verify_only", ["sign_client"], "parse_and_verify"),
    "Argon2Benchmark":        ("Password", "verify_server", [], None),
}

# ── (A.3) BIẾN THỂ VERIFY — chọn qua ENV (để vẽ CẢ 2 bộ figs: normal vs fixed-base comb) ──────────
#   NIPOK_VERIFY=verify_server           (mặc định) → baseline Straus double-scalar (verify cũ)
#   NIPOK_VERIFY=verify_server_prepared            → FBC precompute cho public point (OPT-A, verify mới)
#   FIG_SUFFIX=_fbc  → hậu tố chèn vào TÊN FILE output (figs + table) ⟹ 2 bộ KHÔNG đè nhau.
#   ⚠ FAIR-BASELINE: FBC là tối ưu SCHEME-AGNOSTIC (mọi verify Schnorr-type trên edwards25519) ⟹
#     biến thể FBC áp cho CẢ BA cơ chế cùng nhóm: NIPoK + Schnorr-IZK + Pure-EdDSA (tránh bias
#     "chỉ tune cơ chế Ours"). Private-Key-JWT/mTLS (verify đóng hộp JCA/TLS-stack), ML-DSA (lattice),
#     Password (KDF) — GIỮ NGUYÊN (not applicable).
NIPOK_VERIFY = os.environ.get("NIPOK_VERIFY", "verify_server")
FIG_SUFFIX = os.environ.get("FIG_SUFFIX", "")
FBC = (NIPOK_VERIFY == "verify_server_prepared")
JMH_MAP["NipokBenchmark"] = ("NIPoK", NIPOK_VERIFY, ["prove_client"], None)
if FBC:
    JMH_MAP["SchnorrBenchmark"] = ("Schnorr-IZK", "verify_server_prepared", ["gen_R", "compute_s"], None)
    JMH_MAP["EdDsaAuthBenchmark"] = ("Pure-EdDSA", "verify_server_prepared", ["sign_client"], None)
VARIANT_TAG = ("Verify = fixed-base comb (FBC/OPT-A) for NIPoK, Schnorr-IZK, Pure-EdDSA"
               if FBC else "Verify = Straus double-scalar (library baseline)")

# ── (A.4) TRÌNH BÀY — cấu hình qua ENV, KHÔNG hardcode metadata đo lên hình:
#   JMH_CONFIG  : chuỗi cấu hình đo THẬT (vd "-f5 -wi8 -i10") do script đo truyền vào; rỗng ⟹ không
#                 in config lên hình (tránh title mô tả SAI phương pháp như '-f2' hardcode trước đây).
#   SUBMISSION=1: strip suptitle/variant-tag khỏi hình (bản nộp tạp chí — thông tin chuyển vào caption).
JMH_CONFIG = os.environ.get("JMH_CONFIG", "").strip()
SUBMISSION = os.environ.get("SUBMISSION", "0") == "1"


def _out(fname):
    """Đường dẫn output có chèn FIG_SUFFIX trước phần mở rộng (fig1_x.png → fig1_x_fbc.png)."""
    root, ext = os.path.splitext(fname)
    return os.path.join(OUT_DIR, f"{root}{FIG_SUFFIX}{ext}")


def _save(fig, fname):
    """Lưu PNG 300 DPI + PDF VECTOR song song (Elsevier/FGCS ưu tiên vector cho hình số liệu)."""
    fig.savefig(_out(fname))
    fig.savefig(_out(os.path.splitext(fname)[0] + ".pdf"))


def load_measured():
    """★ Lấy TOÀN BỘ số ĐO (verify/sign/alloc/parse) TỪ JSON kết quả JMH — KHÔNG hardcode. BẮT BUỘC có
    JSON: thiếu/hỏng → RAISE (không nuốt lỗi) để bảng/đồ thị KHÔNG BAO GIỜ vẽ từ số cũ/cố định."""
    if not os.path.exists(JSON_PATH):
        raise FileNotFoundError(
            f"Thiếu {JSON_PATH} — PHẢI chạy JMH benchmark trước rồi mới sinh bảng/đồ thị "
            f"(xem cẩm nang lệnh). KHÔNG có chế độ số hardcode.")
    raw = json.load(open(JSON_PATH))                  # JSONDecodeError nếu hỏng → KHÔNG nuốt → dừng rõ ràng
    sc, al = {}, {}
    for b in raw:
        cls, m = b["benchmark"].split(".")[-2], b["benchmark"].split(".")[-1]
        sc[(cls, m)] = (b["primaryMetric"]["score"], b["primaryMetric"].get("scoreError", 0.0))
        a = b.get("secondaryMetrics", {}).get("·gc.alloc.rate.norm", {}).get("score")
        if a is not None:
            al[(cls, m)] = a / 1024.0
    data = {}
    for cls, (mech, vm, sms, pm) in JMH_MAP.items():
        if (cls, vm) not in sc:
            raise KeyError(f"JSON thiếu kết quả '{cls}.{vm}' — chạy lại JMH đủ 7 benchmark.")
        rec = {"verify": sc[(cls, vm)][0], "verify_err": sc[(cls, vm)][1], "alloc": al.get((cls, vm))}
        svals = [sc[(cls, m)][0] for m in sms if (cls, m) in sc]
        if svals:
            rec["sign"] = float(np.sum(svals))                # sign = tổng cấu phần (Schnorr: gen_R+compute_s)
            rec["sign_err"] = sc[(cls, sms[0])][1]
            rec["sign_alloc"] = al.get((cls, sms[0]))          # alloc SIGN (≠ alloc verify)
        else:
            rec["sign"], rec["sign_alloc"] = None, None        # Password: không ký
        if pm and (cls, pm) in sc:
            rec["parse_verify"] = sc[(cls, pm)][0]             # JWT/mTLS: parse_and_verify
        if cls == "SchnorrBenchmark":
            rec["gen_R"], rec["compute_s"] = sc[(cls, "gen_R")][0], sc[(cls, "compute_s")][0]
            rec["compute_s_alloc"] = al.get((cls, "compute_s"))   # alloc compute_s (≠ gen_R) — từ JSON
        data[mech] = rec
    # GenKey: EC = gen_R ĐO ĐƯỢC (keygen = 1 fixed-base mult); ML-DSA/Password = hằng (không bench keygen).
    ec_genkey = data["Schnorr-IZK"]["gen_R"]
    for mech in ORDER:
        data[mech]["genkey"] = ec_genkey if mech in _EC_GENKEY_MECHS else _GENKEY_CONST[mech]
    print(f"[✓] TOÀN BỘ số đo lấy TỪ {os.path.basename(JSON_PATH)} (genkey EC = gen_R đo được; "
          f"chỉ genkey ML-DSA/Password là hằng — không bench keygen).")
    return data


def cpu_pct(latency_us, rate=1000):
    """CPU% = % MỘT lõi để duy trì `rate` op/s = latency_us * rate / 1e6 * 100. Độc lập, không tạp âm."""
    return latency_us * rate / 1e6 * 100.0


# ════════════════════════════════════════════════════════════════════════════════════════
# (B) BẢNG MARKDOWN (NHIỆM VỤ 2)
# ════════════════════════════════════════════════════════════════════════════════════════
def fmt(v, nd=1):
    if v is None:
        return "—"
    return f"{v/1000:.0f}k" if v >= 10000 else f"{v:.{nd}f}"


def build_tables(d):
    lines = []
    P = lines.append

    # ── Bảng 1: ma trận toàn diện ─────────────────────────────────────────────────────────
    P("## Table 1 — Comprehensive Comparison Matrix (7 schemes)\n")
    cols = ["Mechanism", "Group", "GenKey µs", "Sign µs", "Verify µs", "Alloc KB", "Sig B",
            "CPU%@1k/s", "Payload B", "PubKey B", "RTT", "State", "Anti-Replay", "ZK", "PQ", "RFC"]
    P("| " + " | ".join(cols) + " |")
    P("|" + "|".join(["---"] * len(cols)) + "|")
    for m in ORDER:
        s, x = SPEC[m], d[m]
        name = f"**{m}**" if m == HIGHLIGHT else m
        # genkey EC = gen_R ĐO ĐƯỢC; ML-DSA/Password = ước lượng (không bench keygen) → đánh dấu '≈'.
        gk = ("≈" if m in _GENKEY_CONST else "") + f"{x['genkey']:.1f}"
        P("| " + " | ".join([
            name, GROUP[m], gk, fmt(x['sign']), fmt(x['verify']),
            fmt(x['alloc']), str(s['sig']), f"{cpu_pct(x['verify']):.2f}", str(s['payload']),
            str(s['pubkey']), str(s['rtt']), s['state'], s['antireplay'], s['zk'], s['pq'], s['rfc'],
        ]) + " |")
    P("")

    # ── Bảng 2: VERIFY chi tiết (JWT/mTLS có 2 dòng) ──────────────────────────────────────
    P("## Table 2 — VERIFY Performance (Server)\n")
    P("| Mechanism | Verify µs | Capacity/Core (op/s) | Alloc KB/op | CPU%@1k/s |")
    P("|---|---|---|---|---|")
    for m in ORDER:
        x = d[m]
        rows = [(m, x['verify'], x['alloc'])]
        if "parse_verify" in x:  # JWT/mTLS: tách verify_only vs parse_and_verify
            rows = [(f"{m} · verify_only", x['verify'], x['alloc']),
                    (f"{m} · parse_and_verify", x['parse_verify'], x['alloc'])]
        for label, v, a in rows:
            nm = f"**{label}**" if m == HIGHLIGHT else label
            cap = f"{1e6/v:,.1f}" if v >= 10000 else f"{1e6/v:,.0f}"   # password ~4.6 (KHÔNG để '—')
            P(f"| {nm} | {fmt(v)} | {cap} | {fmt(a)} | {cpu_pct(v):.2f} |")
    P("")

    # ── Bảng 4: SIGN/PROVE chi tiết (Schnorr tách 2 cấu phần) ─────────────────────────────
    P("## Table 4 — SIGN/PROVE Performance (Client)\n")
    P("| Mechanism | Sign/Prove µs | Capacity/Core (op/s) | Alloc KB/op | CPU%@1k/s |")
    P("|---|---|---|---|---|")
    for m in ORDER:
        x = d[m]
        sa = x.get('sign_alloc')              # ★ alloc của SIGN (KHÔNG dùng alloc verify)
        if m == "Schnorr-IZK":  # tách gen_R + compute_s (alloc riêng từng cấu phần)
            for label, v, a in [("Schnorr gen_R", x['gen_R'], sa),                      # sa = alloc gen_R
                                ("Schnorr compute_s", x['compute_s'], x['compute_s_alloc']),
                                ("Schnorr (total)", x['sign'], sa)]:
                cap = f"{1e6/v:,.0f}" if v > 0 else "—"
                P(f"| {label} | {v:.2f} | {cap} | {fmt(a)} | {cpu_pct(v):.2f} |")
            continue
        v = x['sign']
        nm = f"**{m}**" if m == HIGHLIGHT else m
        if v is None:
            P(f"| {nm} | — (no signing, plaintext) | — | — | — |")
        else:
            P(f"| {nm} | {v:.1f} | {1e6/v:,.0f} | {fmt(sa)} | {cpu_pct(v):.2f} |")
    P("")

    # ── Ghi chú tính đúng đắn — SỐ DẪN TỪ DATA (auto-update mỗi lần đo, không hardcode) ────────
    genr = d["Schnorr-IZK"]["gen_R"]                                        # fixed-base mult ĐO ĐƯỢC
    jpv, jv = d["Private-Key-JWT"]["parse_verify"], d["Private-Key-JWT"]["verify"]
    mpv, mv = d["mTLS-PSU"]["parse_verify"], d["mTLS-PSU"]["verify"]
    jdelta, mdelta = jpv - jv, mpv - mv
    P("## Notes (logical consistency & transparency)\n")
    P(f"1. **GenKey**: the 5 EC schemes use the **measured** fixed-base scalar-multiplication "
      f"(gen_R ≈ {genr:.1f} µs, since EC key generation = X = xG). **ML-DSA-65 / Password are NOT "
      f"benchmarked for key-gen** ⟹ shown as estimates (marked '≈' in Table 1); state this in the caption.")
    P(f"2. **Private-Key-JWT**: `parse_and_verify` ({jpv:.1f} µs) and `verify_only` ({jv:.1f} µs) differ "
      f"by only {abs(jdelta):.1f} µs — **within the measurement CI**; the JWT JSON is tiny, so its "
      f"base64+JSON parse cost is *below measurement resolution* (do not over-interpret a within-CI gap). "
      f"For mTLS the parse overhead is REAL: **+{mdelta:.1f} µs** (X.509/XFCC parsing is heavier).")
    P("3. **Password — PubKey 96 B** is actually the stored **PHC (salt+hash)**, not a public key "
      "(Password has no public key). Read it as 'stored credential, 96 B'.")
    P("4. **mTLS-PSU — RTT = 0** means **0 application-layer round-trips** (authentication happens during "
      "the TLS handshake that already takes place); it excludes the TLS handshake's own round-trips.")
    P("5. **Alloc** in Tables 1/2 = **VERIFY** allocation; in Table 4 = **SIGN/PROVE** allocation "
      "(the two allocations differ).")
    P("6. **Radar (Fig. 4) scoring is objective**: the 5 quantitative axes are log-min-max normalized "
      "from the measured latencies/sizes; the 4 qualitative axes (non-interactive, stateless, ZK, PQ) are "
      "DERIVED by a fixed rule from the protocol properties (RTT, State, ZK, PQ in Table 1) — NOT "
      "hand-assigned per scheme.")
    P("")

    txt = "\n".join(lines)
    open(_out("tables_manuscript.md"), "w").write(txt)
    print(f"[✓] {os.path.basename(_out('tables_manuscript.md'))}  ({VARIANT_TAG})")
    return txt


# ════════════════════════════════════════════════════════════════════════════════════════
# (C) CẤU HÌNH THẨM MỸ + ĐỒ THỊ (NHIỆM VỤ 3)
# ════════════════════════════════════════════════════════════════════════════════════════
sns.set_theme(style="whitegrid", context="paper", font="DejaVu Sans")
plt.rcParams.update({
    "figure.dpi": 300, "savefig.dpi": 300, "savefig.bbox": "tight",
    "font.size": 12, "axes.titlesize": 15, "axes.titleweight": "bold",     # ↑ fontsize toàn cục (nhẹ)
    "axes.labelsize": 13, "axes.labelweight": "semibold",
    "xtick.labelsize": 11, "ytick.labelsize": 11, "legend.fontsize": 11,
    "axes.edgecolor": "0.30", "axes.linewidth": 0.9, "grid.alpha": 0.4,
})
CLR_HL = "#1f6fb2"   # màu nhấn NIPoK


def disp(m):
    """Nhãn HIỂN THỊ: NIPoK → 'NIPoK (Ours)' (cơ chế đề xuất). Tên dict (key) giữ nguyên 'NIPoK'."""
    return "NIPoK (Ours)" if m == HIGHLIGHT else m


def _bold_hl_ticks(ax):
    """Bôi đậm + tô màu nhãn trục NIPoK (Ours)."""
    for lbl in ax.get_xticklabels():
        if "NIPoK" in lbl.get_text():
            lbl.set_fontweight("bold")
            lbl.set_color(CLR_HL)


def _bold_hl_legend(leg):
    """Bôi đậm + tô màu mục legend NIPoK (Ours)."""
    for t in leg.get_texts():
        if "NIPoK" in t.get_text():
            t.set_fontweight("bold")
            t.set_color(CLR_HL)


# Bảng màu CHUNG (vivid + tách biệt) — dùng cho fig1 (cột) lẫn fig4 (radar). NIPoK = XANH DUY NHẤT.
MECH_COLORS = {
    "Password": "#555555", "mTLS-PSU": "#ff7f0e", "Private-Key-JWT": "#2ca02c",
    "Pure-EdDSA": "#d62728", "Schnorr-IZK": "#9467bd", "ML-DSA-65": "#8c564b", "NIPoK": CLR_HL,
}


def _mech_legend_handles():
    """Handle legend màu cho 7 cơ chế (NIPoK viền vàng); label NIPoK → 'NIPoK (Ours)'."""
    return [plt.Line2D([0], [0], marker="s", ls="", ms=11, mfc=MECH_COLORS[m],
                       mec="#e8a317" if m == HIGHLIGHT else "0.3",
                       mew=2.2 if m == HIGHLIGHT else 0.6, label=disp(m)) for m in ORDER]


def _bar_panel(ax, mechs, vals, errs, title, ylabel, log=True, est_mask=None):
    colors = [MECH_COLORS[m] for m in mechs]                 # màu THEO CƠ CHẾ (đồng bộ fig4/legend)
    edges = ["#e8a317" if m == HIGHLIGHT else "0.25" for m in mechs]
    lws = [2.6 if m == HIGHLIGHT else 0.7 for m in mechs]    # NIPoK viền vàng dày (nổi bật, không cần nhãn)
    bars = ax.bar(range(len(mechs)), vals, yerr=errs, capsize=3, color=colors,
                  edgecolor=edges, linewidth=lws, error_kw=dict(ecolor="0.3", lw=0.9))
    if est_mask is not None:                                 # giá trị ƯỚC LƯỢNG (không đo JMH) → hatch phân biệt
        for b, is_est in zip(bars, est_mask):
            if is_est:
                b.set_hatch("//")
    if log:
        ax.set_yscale("log")
        ax.yaxis.set_minor_locator(mticker.LogLocator(base=10, subs=np.arange(2, 10) * 0.1))
        ax.grid(axis="y", which="minor", linestyle=":", alpha=0.25)
    ax.grid(axis="y", which="major", alpha=0.5)
    ax.set_axisbelow(True)
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.set_xticks([])                                        # BỎ tên cơ chế dưới cột → dùng legend màu (bottom)
    for i, (b, v) in enumerate(zip(bars, vals)):
        if v is None or (isinstance(v, float) and np.isnan(v)):
            continue
        # ≥10ms → hiển thị ms ("147 ms" thay "146697"); <3µs giữ 1 số lẻ ("0.5" thay "0" trên trục log).
        lab = f"{v/1000:,.0f} ms" if v >= 10000 else (f"{v:.1f}" if v < 3 else f"{v:.0f}")
        if est_mask is not None and est_mask[i]:
            lab = "≈" + lab                                  # ước lượng — khớp ký hiệu '≈' trong Table 1
        ax.annotate(lab, xy=(b.get_x() + b.get_width() / 2, v), xytext=(0, 3),
                    textcoords="offset points", ha="center", va="bottom", fontsize=8.5)


def fig1_bars(d):
    """Bố cục 2-CỘT (manuscript): (a),(b) ở dòng trên; (c) XUỐNG DÒNG, CĂN GIỮA. Tên 7 cơ chế KHÔNG
    để dưới cột mà mã hoá bằng MÀU + legend màu ở BOTTOM (đồng bộ fig4)."""
    gk = [d[m]["genkey"] for m in ORDER]
    sg = [d[m]["sign"] if d[m]["sign"] is not None else np.nan for m in ORDER]
    vf = [d[m]["verify"] for m in ORDER]
    er = [d[m].get("verify_err", 0) for m in ORDER]
    sger = [d[m].get("sign_err", 0) if d[m]["sign"] is not None else 0 for m in ORDER]

    fig = plt.figure(figsize=(12.5, 9.4))
    gs = fig.add_gridspec(2, 4, hspace=0.34, wspace=0.46)
    ax_a = fig.add_subplot(gs[0, 0:2])           # dòng trên — trái
    ax_b = fig.add_subplot(gs[0, 2:4])           # dòng trên — phải
    ax_c = fig.add_subplot(gs[1, 1:3])           # dòng dưới — CĂN GIỮA (cột 2–3 của 4)
    # Panel (a): ML-DSA/Password là HẰNG ƯỚC LƯỢNG (không bench keygen) → hatch '//' + nhãn '≈'
    # (khớp Table 1); 5 cơ chế EC = gen_R ĐO ĐƯỢC (keygen = 1 fixed-base mult) → bar trơn.
    est_a = [m in _GENKEY_CONST for m in ORDER]
    _bar_panel(ax_a, ORDER, gk, None, "(a) Key Generation", "Latency (µs, log scale)", est_mask=est_a)
    _bar_panel(ax_b, ORDER, sg, sger, "(b) Sign / Prove (Client)", "Latency (µs, log scale)")
    _bar_panel(ax_c, ORDER, vf, er, "(c) Verify (Server)", "Latency (µs, log scale)")
    ax_b.annotate("Password: no signing\n(sends plaintext)", xy=(0.03, 0.96),
                  xycoords="axes fraction", ha="left", va="top", fontsize=9.5,
                  style="italic", color="0.4")

    # Legend MÀU 7 cơ chế ở BOTTOM (thay tên dưới mỗi cột) — NIPoK (Ours) đậm.
    leg = fig.legend(handles=_mech_legend_handles(), loc="lower center", ncol=7, frameon=True,
                     framealpha=0.92, bbox_to_anchor=(0.5, 0.005), fontsize=11, columnspacing=1.3,
                     handletextpad=0.4)
    _bold_hl_legend(leg)
    if not SUBMISSION:
        # Config đo lấy từ ENV (JMH_CONFIG do script đo truyền) — KHÔNG hardcode ⟹ không bao giờ
        # mô tả sai phương pháp (trước đây '-f2' hardcode trong khi official đo -f5).
        cfg = f"JMH {JMH_CONFIG}, elisabeth backend" if JMH_CONFIG else "elisabeth backend"
        fig.suptitle("CPU Cost of Three Cryptographic Operations across Seven PSU Authentication Schemes\n"
                     f"({cfg}) — {VARIANT_TAG}", fontsize=14, fontweight="bold", y=0.99)
    fig.tight_layout(rect=[0, 0.055, 1, 0.95 if not SUBMISSION else 0.995])
    _save(fig, "fig1_verify_logbar.png")
    plt.close(fig)
    print(f"[✓] {os.path.basename(_out('fig1_verify_logbar.png'))} (+.pdf)")


def _pareto_front(points):
    pts = sorted(points, key=lambda p: (p[0], p[1]))
    front, best = [], float("inf")
    for x, y, n in pts:
        if y <= best + 1e-9:
            front.append((x, y, n))
            best = y
    return front


def _pareto_panel(ax, mechs, xs, ys, title, xlabel, cmap):
    # NIPoK/Schnorr/Pure-EdDSA gần TRÙNG tọa độ (cùng payload=96) ⟹ vẽ:
    #   • 6 cơ chế khác: marker ĐẶC, alpha 0.8 (chồng nhau vẫn nhìn xuyên) — vẽ TRƯỚC;
    #   • NIPoK: VÒNG VÀNG RỖNG (facecolor='none' ⟹ KHÔNG che điểm dưới) + tâm nhỏ ⟹ ĐỦ 7 điểm hiện.
    for i, m in enumerate(mechs):
        if m == HIGHLIGHT:
            continue
        ax.scatter(xs[i], ys[i], s=170, color=cmap[m], edgecolor="0.2", linewidth=1.0,
                   alpha=0.82, zorder=5)
    j = mechs.index(HIGHLIGHT)
    ax.scatter(xs[j], ys[j], s=480, facecolor="none", edgecolor="#e8a317", linewidth=3.0, zorder=8)
    ax.scatter(xs[j], ys[j], s=85, color=cmap[HIGHLIGHT], edgecolor="white", linewidth=1.0, zorder=9)
    # Frontier tính trên CÁC CƠ CHẾ MẬT MÃ (loại Password — KDF tri-thức, sẽ trội trục CPU).
    front = _pareto_front([(xs[i], ys[i], m) for i, m in enumerate(mechs) if m != "Password"])
    fxs = {round(p[0], 6) for p in front}
    fys = {round(p[1], 6) for p in front}
    if len(fxs) > 1 and len(fys) > 1:
        # Frontier THẬT (≥2 điểm, có độ cong) → vẽ đường + legend như thường.
        ax.plot([p[0] for p in front], [p[1] for p in front], "--", lw=1.8, color="0.45",
                marker="D", markersize=5, markerfacecolor="none", markeredgecolor="0.45",
                zorder=3, label="Pareto frontier (PK schemes)")
        ax.legend(loc="lower right", fontsize=8.5)
    else:
        # SUY BIẾN (cụm Schnorr-type đồng payload 96B → frontier co về đoạn phẳng): KHÔNG vẽ đường +
        # KHÔNG legend tham chiếu một đường không nhìn thấy. Ghi chú dùng phát biểu ĐÚNG CHẶT về
        # dominance: "cụm trội mọi PK scheme khác" (mỗi scheme ngoài cụm bị ≥1 thành viên cụm
        # dominate) — KHÔNG gọi từng thành viên là 'Pareto-optimal' (trong cụm vẫn có weak-dominance,
        # vd Pure-EdDSA bị NIPoK trội ở trục sign). Thành viên + payload dẫn từ data, không hardcode.
        names = " · ".join(disp(p[2]) for p in front)
        ax.annotate(f"{front[0][1]:.0f}-B cluster: {names}\n— Pareto-dominates every other PK scheme",
                    xy=(0.03, 0.03), xycoords="axes fraction",
                    ha="left", va="bottom", fontsize=8.5, style="italic", color="0.35",
                    bbox=dict(boxstyle="round", fc="0.97", ec="0.85"))
    # CHỈ nhãn NIPoK (Ours) — có leader, nổi bật; các cơ chế khác tra legend chung.
    j = mechs.index(HIGHLIGHT)
    ax.annotate(HIGHLIGHT + " (Ours)", xy=(xs[j], ys[j]), xytext=(14, 14),
                textcoords="offset points", ha="left", fontsize=9, fontweight="bold", color=CLR_HL,
                arrowprops=dict(arrowstyle="-", color=CLR_HL, lw=0.9))
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlim(left=min(xs) * 0.45, right=max(xs) * 2.4)
    ax.set_ylim(bottom=min(ys) * 0.45, top=max(ys) * 2.6)
    ax.set_xlabel(xlabel + " (µs, log) ← cheaper")
    ax.set_ylabel("Payload per Auth (bytes, log) ↓ smaller")
    ax.set_title(title)
    ax.grid(which="both", linestyle=":", alpha=0.35)
    _pareto_inset(ax, mechs, xs, ys, cmap)


def _pareto_inset(ax, mechs, xs, ys, cmap):
    """INSET ZOOM góc Pareto-frontier (trái-dưới).

    VÌ SAO CẦN: cụm 96-B (Schnorr-IZK · NIPoK · Pure-EdDSA) có payload TRÙNG NHAU và chi phí CPU
    chỉ chênh vài chục µs ⟹ trên trục log toàn cảnh, ba điểm đè lên nhau và người đọc KHÔNG thấy
    NIPoK nằm đâu trong cụm. Inset phóng to đúng cụm đó (trục x tuyến tính vì dải hẹp) để lộ thứ tự
    theo chi phí CPU — thông tin quyết định của hình mà toàn cảnh không truyền tải được.
    """
    from mpl_toolkits.axes_grid1.inset_locator import inset_axes
    import matplotlib.patches as mpatches
    # Cụm cần phóng: các cơ chế có payload NHỎ NHẤT (frontier), loại Password.
    pay_min = min(ys[i] for i, m in enumerate(mechs) if m != "Password")
    grp = sorted([(xs[i], m) for i, m in enumerate(mechs)
                  if m != "Password" and abs(ys[i] - pay_min) < 1e-9])
    if len(grp) < 2:
        return                                     # không có cụm chồng ⟹ inset vô nghĩa

    # DOT-PLOT NGANG (không phải scatter x-y): trong cụm này payload BẰNG NHAU nên trục y của
    # toàn cảnh không mang thông tin. Dùng y làm HÀNG cho từng cơ chế ⟹ nhãn không thể chồng
    # (Pure-EdDSA 55.2 vs NIPoK 55.1 chênh 0.08 µs — scatter sẽ trùng điểm và trùng nhãn).
    gx = [p[0] for p in grp]
    span = max(max(gx) - min(gx), max(gx) * 0.02)
    # borderpad LỚN (đơn vị = cỡ chữ): tiêu đề inset dài 2 dòng nằm PHÍA TRÊN trục inset, nên
    # borderpad nhỏ (1.1) làm tiêu đề nhô ra và đè viền trên của panel. 2.9 chừa đủ chỗ 2 dòng.
    axin = inset_axes(ax, width="44%", height="30%", loc="upper right", borderpad=2.9)
    for k, (x, m) in enumerate(grp):
        hl = (m == HIGHLIGHT)
        axin.hlines(k, min(gx) - span * 0.45, x, color="0.78", lw=1.0, zorder=1)
        axin.scatter(x, k, s=300 if hl else 120,
                     facecolor="none" if hl else cmap[m],
                     edgecolor="#e8a317" if hl else "0.25",
                     linewidth=2.4 if hl else 0.9, zorder=6)
        if hl:
            axin.scatter(x, k, s=60, color=cmap[m], edgecolor="white", linewidth=0.8, zorder=7)
        axin.annotate(f"{x:.1f} µs", (x, k), textcoords="offset points", xytext=(11, 0),
                      va="center", fontsize=7.2, fontweight="bold" if hl else "normal",
                      color=CLR_HL if hl else "0.3")
    axin.set_yticks(range(len(grp)))
    axin.set_yticklabels([disp(m) for _, m in grp], fontsize=7.2)
    for lbl, (_, m) in zip(axin.get_yticklabels(), grp):
        if m == HIGHLIGHT:
            lbl.set_color(CLR_HL); lbl.set_fontweight("bold")
    axin.set_ylim(-0.7, len(grp) - 0.3)
    axin.set_xlim(min(gx) - span * 0.5, max(gx) + span * 0.85)
    axin.tick_params(axis="x", labelsize=6.8)
    axin.set_title(f"zoom: {pay_min:.0f}-B cluster — identical payload,\nCPU cost only "
                   "(← cheaper)", fontsize=7.2, pad=3)
    axin.grid(axis="x", linestyle=":", alpha=0.4)
    for s in axin.spines.values():
        s.set_color("0.45")
    axin.set_facecolor("#fbfbfa")

    # Khung nét đứt quanh cụm trên TOÀN CẢNH + nhãn trỏ tới inset (thay mark_inset: trục y của
    # inset là chỉ số hàng, không cùng hệ toạ độ nên connector tự động sẽ vẽ sai).
    x0, x1 = min(gx), max(gx)
    ax.add_patch(mpatches.Rectangle(
        (x0 * 0.80, pay_min * 0.80), x1 * 1.25 - x0 * 0.80, pay_min * 0.45,
        fill=False, ec="0.5", lw=1.1, ls="--", zorder=4))
    # KHÔNG thêm nhãn "see zoom": mọi vị trí thử đều đè lên thứ khác (hộp chú thích cụm ở panel a,
    # nhãn NIPoK ở panel b). Khung nét đứt + tiêu đề inset "zoom: NN-B cluster" đã đủ chỉ dẫn.


def fig2_pareto(d):
    """2 PANEL (Sign, Verify) — panel Key-Generation ĐÃ BỎ (theo review): genkey của 5 cơ chế EC là
    DẪN XUẤT từ cùng gen_R ⟹ 5 điểm trùng toạ độ, không có nội dung so sánh (keygen đã có fig1(a)).
    Password KHÔNG có phép ký ⟹ LOẠI khỏi panel Sign (trước đây vẽ điểm 'sàn 0.3µs' nguỵ tạo) + ghi
    chú. Màu = MECH_COLORS (đồng bộ fig1/fig4); legend màu CHUNG ở bottom."""
    cmap = MECH_COLORS                                        # đồng bộ màu với fig1/fig4
    mech_s = [m for m in ORDER if d[m]["sign"] is not None]   # panel Sign: chỉ cơ chế CÓ phép ký
    sg = [d[m]["sign"] for m in mech_s]
    pay_s = [SPEC[m]["payload"] for m in mech_s]
    vf = [d[m]["verify"] for m in ORDER]
    pay_v = [SPEC[m]["payload"] for m in ORDER]

    fig, (ax_a, ax_b) = plt.subplots(1, 2, figsize=(12.5, 6.4))
    _pareto_panel(ax_a, mech_s, sg, pay_s, "(a) Payload vs. Sign / Prove (Client)", "Sign / Prove", cmap)
    ax_a.annotate("Password: no signing\n(sends plaintext) — not shown", xy=(0.03, 0.97),
                  xycoords="axes fraction", ha="left", va="top", fontsize=9,
                  style="italic", color="0.4")
    _pareto_panel(ax_b, ORDER, vf, pay_v, "(b) Payload vs. Verify (Server)", "Verify", cmap)

    leg = fig.legend(handles=_mech_legend_handles(), loc="lower center", ncol=7, frameon=True,
                     framealpha=0.92, bbox_to_anchor=(0.5, 0.005), fontsize=11, columnspacing=1.3,
                     handletextpad=0.4)
    _bold_hl_legend(leg)
    if not SUBMISSION:
        fig.suptitle("Payload–CPU Pareto Trade-off per Authentication (lower-left is optimal)\n"
                     f"— {VARIANT_TAG}",
                     fontsize=14, fontweight="bold", y=0.99)
    fig.tight_layout(rect=[0, 0.09, 1, 0.90 if not SUBMISSION else 0.995])
    _save(fig, "fig2_pareto.png")
    plt.close(fig)
    print(f"[✓] {os.path.basename(_out('fig2_pareto.png'))} (2 panels, frontier-degeneracy handled, +.pdf)")


def fig3_diverging(d):
    """DIVERGING (back-to-back) barh — "ai trả CPU?": Verify mọc TRÁI (Bank domain), Sign/Prove mọc
    PHẢI (Customer domain); trục giữa 0 = TRUST BOUNDARY. Thay stacked cũ vì: (1) Σ=V+S cộng chéo
    2 miền tin cậy là đại lượng không bên nào chi trả; (2) stacked làm segment trên mất baseline;
    (3) linear-scale bị ML-DSA nén cụm µs. Ở đây: mỗi phía chung baseline 0 ⟹ so được cả V lẫn S
    bằng mắt; outlier (ML-DSA sign, Password verify) CLIP tại mép + nhãn GIÁ TRỊ THẬT; đủ 7 cơ chế;
    có CI whisker (JMH scoreError). Màu theo SERIES (blue/orange, CVD-safe ΔE≈89, đã validate)."""
    C_V, C_S = "#3567a6", "#d97a2f"          # Verify (server) / Sign (client) — cặp blue-orange
    INK, MUT = "0.15", "0.42"                 # chữ = mực (không tô màu series lên text)
    # Hàng cố định top→bottom (modern → traditional, Ours trên cùng) — GIỐNG NHAU giữa 2 biến thể
    # normal/_fbc ⟹ so trước–sau theo từng hàng được.
    rows = ["NIPoK", "Schnorr-IZK", "Pure-EdDSA", "ML-DSA-65", "Private-Key-JWT", "mTLS-PSU", "Password"]
    CLIP = 130.0                              # µs — phủ trọn cụm µs-class (verify ML-DSA ~110µs)

    fig, ax = plt.subplots(figsize=(10.6, 6.2))
    y = np.arange(len(rows))[::-1]            # hàng đầu danh sách nằm TRÊN cùng
    H = 0.62                                  # bar mảnh + khe thoáng giữa hàng

    def bar_one(yi, val, err, side, color):
        """Vẽ 1 thanh (side=-1 trái/verify, +1 phải/sign); clip nếu vượt CLIP → nhãn giá trị thật."""
        clipped = val > CLIP
        w = side * min(val, CLIP)
        ax.barh(yi, w, H, color=color, edgecolor="white", linewidth=0.8, zorder=4)
        if clipped:                           # ký hiệu đứt trục ∕∕ trên thân + giá trị thật ngoài mép
            ax.annotate("∕∕", xy=(side * CLIP * 0.93, yi), ha="center", va="center",
                        fontsize=11, fontweight="bold", color="white", zorder=6)
            lab = f"{val/1000:,.0f} ms" if val >= 10000 else f"{val:,.0f} µs"
            ax.annotate(("◀ " if side < 0 else "") + lab + (" ▶" if side > 0 else ""),
                        xy=(side * CLIP, yi), xytext=(side * 5, 0), textcoords="offset points",
                        ha="left" if side > 0 else "right", va="center",
                        fontsize=9, fontweight="bold", color=INK, zorder=6)
        else:                                 # CI whisker (JMH scoreError) + nhãn giá trị (màu mực)
            if err:
                ax.errorbar(w, yi, xerr=err, fmt="none", ecolor="0.35", elinewidth=1.0,
                            capsize=2.5, zorder=5)
            ax.annotate(f"{val:.0f}", xy=(w, yi), xytext=(side * (10 if err else 5), 0),
                        textcoords="offset points", ha="left" if side > 0 else "right",
                        va="center", fontsize=9.5, color=INK, zorder=6)

    for yi, m in zip(y, rows):
        x = d[m]
        bar_one(yi, x["verify"], x.get("verify_err"), -1, C_V)
        if x["sign"] is not None:
            bar_one(yi, x["sign"], x.get("sign_err"), +1, C_S)
        else:                                 # Password: không ký (plaintext) — ghi chú, không vẽ thanh
            ax.annotate("no signing (plaintext)", xy=(5, yi), ha="left", va="center",
                        fontsize=9, style="italic", color=MUT)
        if m == HIGHLIGHT:                    # viền vàng quanh CẢ HÀNG NIPoK (quy ước chung các fig)
            w_l, w_r = -min(x["verify"], CLIP), min(x["sign"] or 0, CLIP)
            ax.barh(yi, w_r - w_l, H, left=w_l, fill=False, edgecolor="#e8a317",
                    linewidth=2.6, zorder=7)

    # Trục giữa = TRUST BOUNDARY (luận điểm kiến trúc của paper)
    ax.axvline(0, color="0.2", lw=1.4, zorder=3)
    ax.annotate("trust boundary", xy=(0, -0.62), ha="center", va="top", fontsize=9,
                style="italic", color=MUT, rotation=0, annotation_clip=False)
    # Header 2 miền (chữ = mực; màu series do legend đảm nhận) — có band riêng, không đè viền khung
    ax.annotate("◀  Verify — Bank domain (server)", xy=(-CLIP * 0.98, len(rows) - 0.15),
                ha="left", va="bottom", fontsize=11, fontweight="bold", color=INK)
    ax.annotate("Sign / Prove — Customer domain (client)  ▶", xy=(CLIP * 0.98, len(rows) - 0.15),
                ha="right", va="bottom", fontsize=11, fontweight="bold", color=INK)

    ax.set_xlim(-CLIP * 1.22, CLIP * 1.22)
    ax.set_ylim(-0.8, len(rows) + 0.42)
    ax.set_yticks(y)
    ax.set_yticklabels([disp(m) for m in rows], fontsize=11)
    for lbl in ax.get_yticklabels():
        if "NIPoK" in lbl.get_text():
            lbl.set_fontweight("bold")
            lbl.set_color(CLR_HL)
    ax.xaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{abs(v):.0f}"))
    ax.set_xlabel(f"Cryptographic CPU time per authentication (µs; ∕∕ = truncated at {CLIP:.0f} µs, "
                  "true value labeled)", fontsize=12)
    if not SUBMISSION:
        ax.set_title("Cryptographic CPU-Cost Allocation across the Trust Boundary\n"
                     f"{VARIANT_TAG}", fontsize=13)
    ax.grid(axis="x", alpha=0.4)
    ax.grid(axis="y", visible=False)
    ax.set_axisbelow(True)
    leg = ax.legend(handles=[
        plt.Rectangle((0, 0), 1, 1, fc=C_V, ec="none", label="Verify (Server)"),
        plt.Rectangle((0, 0), 1, 1, fc=C_S, ec="none", label="Sign/Prove (Client)")],
        loc="lower right", frameon=True, framealpha=0.92, fontsize=10)
    fig.tight_layout()
    _save(fig, "fig3_grouped.png")
    plt.close(fig)
    print(f"[✓] {os.path.basename(_out('fig3_grouped.png'))} (diverging trust-boundary, +.pdf)")


# Radar 7 trục + 2 trục bổ sung (GC-light, Storage-light) = 9 trục; điểm 0-1 (cao=tốt).
# Định lượng (verify/sign/payload/alloc/pubkey) log-chuẩn-hoá trong code; định tính = sự thật giao thức.
# 4 trục ĐỊNH TÍNH của radar [non_interactive, stateless, zk, pq] được DẪN TỪ SPEC (ánh xạ XÁC ĐỊNH
# từ tính chất giao thức) — KHÔNG gán tay từng cơ chế ⟹ KHÁCH QUAN, tái lập được.
#   • non_interactive = f(rtt): ≤1 round-trip (1-pass / handshake) → 1.0; 2-pass tương tác → 0.3
#   • stateless       = f(state): stateless→1.0 · nonce/jti-store (bounded)→0.6 · session-store (nặng)→0.2
#   • zk / pq         = trực tiếp từ cờ ✓/✗ trong SPEC
_STATELESS_SCORE = {"stateless": 1.0, "nonce-store": 0.6, "jti-store": 0.6, "session-store": 0.2}


def _qual_scores(m):
    s = SPEC[m]
    return [
        1.0 if s["rtt"] <= 1 else 0.3,        # non-interactive (từ RTT)
        _STATELESS_SCORE[s["state"]],          # stateless (từ State)
        1.0 if s["zk"] == "✓" else 0.0,        # zero-knowledge (cờ SPEC)
        1.0 if s["pq"] == "✓" else 0.0,        # post-quantum (cờ SPEC)
    ]


def _lognorm_inv(vals):
    """Chuẩn-hoá 'nhỏ=tốt' về [0,1] theo log (1=nhỏ nhất). Ổn định với outlier (password)."""
    lv = np.log10(np.array(vals, float))
    lo, hi = lv.min(), lv.max()
    return list(1 - (lv - lo) / (hi - lo + 1e-12))


def _radar_scores(d):
    """Điểm radar 0–1 (cao=tốt) cho 9 trục + nhãn trục — DÙNG CHUNG fig4 (chồng) & fig4.1 (small-multiples).
    Trục #1 = Capacity/Core (= 1/verify_µs chuẩn-hoá; KHÔNG thêm trục latency riêng để tránh double-count)."""
    axes_lbl = ["Capacity/Core\n(verify op/s)", "Cheap Client\n(Agent CPU)", "Compact\nPayload",
                "Low GC\n(alloc)", "Compact\nPubKey", "Non-\ninteractive", "Stateless",
                "Zero-\nKnowledge", "Post-\nQuantum"]
    vfit = _lognorm_inv([d[m]["verify"] for m in ORDER])
    sfit = _lognorm_inv([d[m]["sign"] if d[m]["sign"] else 1.0 for m in ORDER])
    pfit = _lognorm_inv([SPEC[m]["payload"] for m in ORDER])
    afit = _lognorm_inv([d[m]["alloc"] for m in ORDER])
    kfit = _lognorm_inv([SPEC[m]["pubkey"] for m in ORDER])
    scores = {m: [vfit[i], sfit[i], pfit[i], afit[i], kfit[i]] + _qual_scores(m)
              for i, m in enumerate(ORDER)}
    return scores, axes_lbl


def fig4_radar(d):
    scores, axes_lbl = _radar_scores(d)
    n = len(axes_lbl)
    ang = np.linspace(0, 2 * np.pi, n, endpoint=False).tolist()
    ang += ang[:1]
    # Dùng CHUNG bảng màu MECH_COLORS (đồng bộ fig1): NIPoK là XANH DUY NHẤT (chống nhầm với Password).
    fig, ax = plt.subplots(figsize=(10.8, 10.8), subplot_kw=dict(polar=True))   # to hơn → chỗ cho nhãn ngoài
    for m in ORDER:
        hl = (m == HIGHLIGHT)
        c = MECH_COLORS[m]
        v = scores[m] + scores[m][:1]
        # nét hơn: line dày + đậm (alpha cao) cho mọi cơ chế; NIPoK nổi bật nhất.
        ax.plot(ang, v, lw=3.8 if hl else 2.2, color=c,
                marker="o", markersize=6.5 if hl else 4.5, label=f"{m} (Ours)" if hl else m,
                zorder=7 if hl else 3, alpha=1.0 if hl else 0.95)
        ax.fill(ang, v, color=c, alpha=0.25 if hl else 0.07)
    ax.set_xticks(ang[:-1])
    ax.set_xticklabels(axes_lbl, fontsize=12.5)              # ↑ font nhãn trục (theo yêu cầu)
    ax.tick_params(axis="x", pad=12)                          # SÁT vòng tròn hơn (vẫn không đè nhờ căn-lề-theo-góc)
    # Căn lề nhãn THEO GÓC: nhãn bên PHẢI (Capacity/Core, 3 giờ) → căn TRÁI ⟹ lệch hẳn ra ngoài;
    # nhãn bên TRÁI (Compact PubKey, 9 giờ) → căn PHẢI. Nhãn trên/dưới giữ căn giữa.
    for lbl, a in zip(ax.get_xticklabels(), ang[:-1]):
        ca = np.cos(a)
        lbl.set_horizontalalignment("left" if ca > 0.25 else "right" if ca < -0.25 else "center")
    ax.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_yticklabels(["0.2", "0.4", "0.6", "0.8", "1.0"], fontsize=9.5, color="0.45")
    ax.set_ylim(0, 1.0)
    ax.grid(alpha=0.4)
    if not SUBMISSION:
        # KHÔNG claim "larger area = better balance" — diện tích radar phụ thuộc THỨ TỰ TRỤC (tùy ý)
        # nên không phải thước đo hợp lệ; chỉ nói "outer = better" TRÊN TỪNG TRỤC.
        ax.set_title("Multi-Criteria Profile (9 axes) of Seven PSU Authentication Schemes\n"
                     f"(normalized scores 0–1; outer = better on each axis) — {VARIANT_TAG}",
                     pad=32)
    leg = ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.07), ncol=4, frameon=True, framealpha=0.92)
    _bold_hl_legend(leg)
    fig.tight_layout()
    _save(fig, "fig4_radar.png")
    plt.close(fig)
    print(f"[✓] {os.path.basename(_out('fig4_radar.png'))} (+.pdf)")


def fig4b_radar_small(d):
    """SMALL-MULTIPLES: 7 radar nhỏ (mỗi cơ chế 1 ô) + 1 ô CHÚ GIẢI trục, CÙNG thang 0–1. Mỗi ô overlay
    đường NIPoK (Ours) nét đứt làm THAM CHIẾU ⟹ so từng cơ chế với 'Ours' tức thì. Sạch hơn cho bản in
    (không chồng 7 đa giác rối như fig4)."""
    scores, axes_lbl = _radar_scores(d)
    n = len(axes_lbl)
    ang = np.linspace(0, 2 * np.pi, n, endpoint=False).tolist()
    ang += ang[:1]
    ref = scores[HIGHLIGHT] + scores[HIGHLIGHT][:1]            # hồ sơ NIPoK (tham chiếu)

    fig = plt.figure(figsize=(15, 8.4))
    gs = fig.add_gridspec(2, 4, hspace=0.45, wspace=0.32)
    for idx, m in enumerate(ORDER):
        r, c = divmod(idx, 4)
        ax = fig.add_subplot(gs[r, c], polar=True)
        col = MECH_COLORS[m]
        v = scores[m] + scores[m][:1]
        if m != HIGHLIGHT:                                    # overlay NIPoK tham chiếu (trừ chính ô NIPoK)
            ax.plot(ang, ref, lw=1.1, color=CLR_HL, alpha=0.40, ls="--", zorder=2)
        ax.plot(ang, v, lw=2.4, color=col, marker="o", markersize=3.2, zorder=4)
        ax.fill(ang, v, color=col, alpha=0.30, zorder=3)
        ax.set_title(disp(m), fontsize=12.5, pad=10,
                     fontweight="bold" if m == HIGHLIGHT else "semibold",
                     color=CLR_HL if m == HIGHLIGHT else "0.15")
        ax.set_xticks(ang[:-1])
        ax.set_xticklabels([str(i + 1) for i in range(n)], fontsize=9, color="0.4")  # đánh SỐ trục (1–9)
        ax.tick_params(axis="x", pad=1)
        ax.set_yticks([0.25, 0.5, 0.75, 1.0])
        ax.set_yticklabels([])                                # bỏ nhãn bán kính cho gọn
        ax.set_ylim(0, 1.0)
        ax.grid(alpha=0.35)

    # Ô thứ 8 = CHÚ GIẢI: số trục → tên tiêu chí + ghi chú đường tham chiếu.
    keyax = fig.add_subplot(gs[1, 3])
    keyax.axis("off")
    key = "\n".join(f"{i + 1}.  {axes_lbl[i].replace(chr(10), ' ')}" for i in range(n))
    keyax.text(0.02, 0.99, "Axes (criteria):", fontsize=12.5, fontweight="bold", va="top")
    keyax.text(0.05, 0.87, key, fontsize=11, va="top")
    keyax.text(0.02, 0.06, "– – –  NIPoK (Ours) overlaid as reference\n"
               "(outer = better on each axis; same 0–1 scale)",
               fontsize=10, style="italic", color=CLR_HL, va="bottom")

    if not SUBMISSION:
        fig.suptitle("Per-Scheme Multi-Criteria Radar — Small Multiples "
                     "(same 0–1 scale; dashed = NIPoK (Ours) reference)\n"
                     f"{VARIANT_TAG}",
                     fontsize=15, fontweight="bold", y=1.0)
    fig.tight_layout(rect=[0, 0, 1, 0.96 if not SUBMISSION else 1.0])
    _save(fig, "fig4.1_radar.png")
    plt.close(fig)
    print(f"[✓] {os.path.basename(_out('fig4.1_radar.png'))} (+.pdf)")


# ════════════════════════════════════════════════════════════════════════════════════════
def main():
    d = load_measured()
    print("\n===== BẢNG (markdown) =====")
    print(build_tables(d))
    print("===== ĐỒ THỊ (300 DPI) =====")
    fig1_bars(d)
    fig2_pareto(d)
    fig3_diverging(d)
    fig4_radar(d)
    fig4b_radar_small(d)
    print("\nHoàn tất: tables_manuscript.md + fig1..fig4 + fig4.1 (.png).")


if __name__ == "__main__":
    main()
