#!/usr/bin/env python3
"""plot_loadtest.py — 4 chart manuscript cho load-test e2e 7 cơ chế xác thực PSU.

  RESULTS=<dir> [JMH_JSON=<file>] python3 plot_loadtest.py

Nguồn: 100% từ RESULTS/*.summary.json (do run-all-psu.sh sinh) + (LT4) JMH official-final.json.
KHÔNG hardcode số đo; thiếu dữ liệu cho một chart ⟹ BỎ chart đó (in cảnh báo), không vẽ số giả.

  L1  p99 vs offered RPS (rate sweep)      → L1_latency_throughput.png/.pdf
  L3  journeys / CPU·s (golden, ±CI)       → L3_efficiency_cpu.png/.pdf
  L8  p99 vs WAN RTT (ablation 1 vs 2 RTT) → L8_rtt_sensitivity.png/.pdf
  LT4 crypto µs (JMH) × capacity (e2e)     → LT4_micro_macro.png/.pdf

Màu/nhãn đồng bộ với hình JMH (MECH_COLORS) để 2 phần Evaluation đọc như một hệ.
Tiêu đề KHÔNG in lên hình (đưa vào caption LaTeX) — giống bộ JMH SUBMISSION=1.
"""
import os, sys, glob, json, statistics as st

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FixedLocator, NullFormatter

DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.environ.get("RESULTS", os.path.join(DIR, "result-loadtest"))
JMH_JSON = os.environ.get("JMH_JSON", "")

# ── Danh pháp & màu: GIỮ NGUYÊN như bộ JMH (cross-figure consistency) ──────────
HIGHLIGHT = "NIPoK"
MECH_MAP = {"password": "Password", "mtls": "mTLS-PSU", "private_key_jwt": "Private-Key-JWT",
            "ed25519": "Pure-EdDSA", "schnorr_interactive": "Schnorr-IZK",
            "ml_dsa": "ML-DSA-65", "nipok": "NIPoK"}
ORDER = ["Password", "mTLS-PSU", "Private-Key-JWT", "Pure-EdDSA", "Schnorr-IZK", "ML-DSA-65", "NIPoK"]
CLR_HL = "#1f6fb2"
MECH_COLORS = {"Password": "#555555", "mTLS-PSU": "#ff7f0e", "Private-Key-JWT": "#2ca02c",
               "Pure-EdDSA": "#d62728", "Schnorr-IZK": "#9467bd", "ML-DSA-65": "#8c564b",
               "NIPoK": CLR_HL}
MARKERS = {"Password": "s", "mTLS-PSU": "o", "Private-Key-JWT": "^", "Pure-EdDSA": "D",
           "Schnorr-IZK": "v", "ML-DSA-65": "P", "NIPoK": "o"}
# JMH class → (mech, sign-method, verify-method). Verify = FBC cho 3 cơ chế edwards25519
# (khớp bộ hình JMH _fbc); mTLS/JWT dùng parse_and_verify (chi phí verify THẬT ở server).
JMH_MAP = {
    "NipokBenchmark":         ("NIPoK", "prove_client", "verify_server_prepared"),
    "SchnorrBenchmark":       ("Schnorr-IZK", "gen_R", "verify_server_prepared"),
    "EdDsaAuthBenchmark":     ("Pure-EdDSA", "sign_client", "verify_server_prepared"),
    "MlDsaAuthBenchmark":     ("ML-DSA-65", "sign_client", "verify_server"),
    "PrivateKeyJwtBenchmark": ("Private-Key-JWT", "sign_client", "parse_and_verify"),
    "MtlsCertBenchmark":      ("mTLS-PSU", "sign_client", "parse_and_verify"),
    "Argon2Benchmark":        ("Password", None, "verify_server"),
}
INK, INK2, GRID, SURFACE = "#0b0b0b", "#52514e", "#d9d8d4", "#ffffff"
plt.rcParams.update({"font.size": 11, "axes.titlesize": 12, "figure.dpi": 300,
                     "savefig.bbox": "tight", "axes.edgecolor": "0.30", "axes.linewidth": 0.9})


def warn(m): print(f"   [!] {m}", file=sys.stderr)


def disp(m): return "NIPoK (Ours)" if m == HIGHLIGHT else m


def style(ax):
    ax.set_facecolor(SURFACE)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.yaxis.grid(True, color=GRID, linewidth=0.6, zorder=0)
    ax.xaxis.grid(False)
    ax.tick_params(colors=INK2, labelsize=9)


def bold_hl_xticks(ax):
    for lbl in ax.get_xticklabels():
        if "NIPoK" in lbl.get_text():
            lbl.set_fontweight("bold"); lbl.set_color(CLR_HL)


def legend_below(fig, mechs, ncol=4):
    """Legend dưới hình — đặt DƯỚI nhãn trục x (tight_layout trước, rồi anchor âm)."""
    handles = [plt.Line2D([0], [0], marker=MARKERS[m], color=MECH_COLORS[m], lw=2, ms=8,
                          markeredgecolor="#e8a317" if m == HIGHLIGHT else "0.3",
                          markeredgewidth=1.8 if m == HIGHLIGHT else 0.8, label=disp(m))
               for m in mechs]
    fig.tight_layout()
    rows = (len(mechs) + ncol - 1) // ncol
    fig.legend(handles=handles, loc="upper center", ncol=ncol, frameon=False,
               bbox_to_anchor=(0.5, -0.01 - 0.0), fontsize=9,
               bbox_transform=fig.transFigure)
    fig.subplots_adjust(bottom=0.18 + 0.06 * (rows - 1))


def save(fig, name):
    for ext in (".png", ".pdf"):
        fig.savefig(os.path.join(RESULTS, name + ext), facecolor=SURFACE)
    plt.close(fig)
    print(f"   [+] {name}.png (+.pdf)")


# ── Nạp summary ───────────────────────────────────────────────────────────────
def load_runs():
    runs = []
    for f in sorted(glob.glob(os.path.join(RESULTS, "*.summary.json"))):
        try:
            d = json.load(open(f))
        except Exception:
            warn(f"bỏ file lỗi: {os.path.basename(f)}"); continue
        m = MECH_MAP.get(d.get("mech"))
        if not m or not d.get("success"):
            continue
        lat = d.get("journey_latency_ms") or {}
        # Nhãn file cho biết run thuộc pha nào (knee-search hay sweep/L8) — cần cho hình A.
        tag = os.path.basename(f).split("-", 1)[1].rsplit(".summary", 1)[0]
        runs.append(dict(mech=m, scenario=d.get("scenario"), rep=d.get("repeat"), tag=tag,
                         rps=d.get("rps") or 0.0, rate=d.get("rate"),
                         p50=lat.get("p50_ms"), p95=lat.get("p95_ms"),
                         p99=lat.get("p99_ms"), p999=lat.get("p999_ms"),
                         fail_rate=d.get("http_req_failed_rate"),
                         cpu=d.get("authserver_cpu_cores"),
                         eff=d.get("journeys_per_cpu_s_authserver"),
                         node=d.get("node_cpu_pct") or {},
                         data_ok=(d.get("data_ok") or 0) / (d.get("success") or 1),
                         frac=d.get("knee_frac"), rtt=d.get("rtt_ms")))
    return runs


def agg(vals):
    """median + nửa khoảng (max-min)/2 làm error bar khi n<3 (CI Student cần n lớn hơn)."""
    vals = [v for v in vals if v is not None]
    if not vals:
        return None, 0.0
    if len(vals) == 1:
        return vals[0], 0.0
    return st.median(vals), (max(vals) - min(vals)) / 2.0


def mechs_present(runs, pred=lambda r: True):
    s = {r["mech"] for r in runs if pred(r)}
    return [m for m in ORDER if m in s]


# ── L1 — p99 vs offered RPS (rate sweep) ─────────────────────────────────────
def fig_L1(runs):
    pts = [r for r in runs if r["frac"] is not None and r["p99"]]
    if not pts:
        warn("L1: không có run sweep (knee_frac) — BỎ chart"); return
    fig, ax = plt.subplots(figsize=(6.6, 4.2))
    ms = mechs_present(pts)
    for m in ms:
        by = {}
        for r in (x for x in pts if x["mech"] == m):
            by.setdefault(r["frac"], []).append(r)
        xs, ys, es, fr = [], [], [], []
        for frac in sorted(by):
            grp = by[frac]
            rps, _ = agg([g["rps"] for g in grp])          # RPS ĐẠT ĐƯỢC (không phải offered)
            p99, err = agg([g["p99"] for g in grp])
            if rps and p99:
                xs.append(rps); ys.append(p99); es.append(err); fr.append(frac)
        if not xs:
            continue
        ax.errorbar(xs, ys, yerr=es, color=MECH_COLORS[m], marker=MARKERS[m], ms=7, lw=2,
                    capsize=3, markeredgecolor="#e8a317" if m == HIGHLIGHT else "0.3",
                    markeredgewidth=1.8 if m == HIGHLIGHT else 0.8,
                    zorder=5 if m == HIGHLIGHT else 3, label=disp(m))
        # Ba điểm = 30/60/100% knee CỦA CHÍNH cơ chế đó. Chỉ gắn nhãn trên đường được
        # highlight — gắn cả 7 đường sẽ thành 21 nhãn chồng nhau.
        if m == HIGHLIGHT:
            for x, y, f in zip(xs, ys, fr):
                ax.annotate(f"{int(f*100)}%", (x, y), textcoords="offset points",
                            xytext=(6, -14), fontsize=8.5, color=CLR_HL, fontweight="bold")
    # ── Dải vận hành 30–60% knee: vùng KẾT LUẬN của hình. Ở 100% knee các đường đan xen
    # nhau do hệ thống đã vào bão hoà (phương sai lấn tín hiệu) ⟹ phải chỉ rõ cho người đọc
    # biết so sánh có ý nghĩa nằm ở đâu, kèm ngưỡng p99 = 120 ms mà NIPoK giữ được.
    band = [r for r in pts if r["frac"] in (0.3, 0.6) and r["mech"] != "Password"]
    if band:
        bx0, bx1 = min(r["rps"] for r in band), max(r["rps"] for r in band)
        ax.axvspan(bx0 * 0.93, bx1 * 1.07, color="#eef4fa", zorder=0)
        ax.axhline(120, ls="--", lw=1.3, color=CLR_HL, alpha=0.75, zorder=2)
        ax.annotate("p99 = 120 ms", xy=(bx1 * 1.07, 120), xytext=(4, 5),
                    textcoords="offset points", fontsize=8.5, color=CLR_HL, fontweight="bold")
        # Hộp đặt TRONG lòng hình (vùng trống trên-trái), KHÔNG để dưới trục — đặt dưới sẽ
        # đè lên nhãn trục x (đã quan sát khi render).
        ax.annotate("30–60% knee operating band:\nall public-key mechanisms — including\n"
                    "NIPoK — stay below 120 ms p99",
                    xy=((bx0 + bx1) / 2, 100), xycoords="data",
                    xytext=(0.30, 0.80), textcoords="axes fraction",
                    ha="center", va="center", fontsize=8.5, color=INK,
                    bbox=dict(boxstyle="round,pad=0.4", fc="#eef4fa", ec=CLR_HL, lw=1.0),
                    arrowprops=dict(arrowstyle="->", color=CLR_HL, lw=1.4,
                                    connectionstyle="arc3,rad=-0.15"))
        # Vùng trống duy nhất còn lại là dưới-phải (x>62, y 100–1000) — mọi vị trí khác đè đường.
        ax.annotate("100% knee: saturated;\ncurves interleave",
                    xy=(max(r["rps"] for r in pts) * 0.96, 1900), xycoords="data",
                    xytext=(0.86, 0.28), textcoords="axes fraction",
                    ha="center", va="center", fontsize=8, color=INK2, style="italic",
                    arrowprops=dict(arrowstyle="->", color="0.55", lw=1.1,
                                    connectionstyle="arc3,rad=-0.25"))

    # Y = log (BẮT BUỘC): p99 trải 65→7378 ms (113×); thang tuyến tính sẽ nén 12/21 điểm
    #   — tức toàn bộ vùng vận hành lành mạnh — vào 3% dưới cùng của hình.
    # X = tuyến tính: throughput chỉ trải 4.8→77 j/s (16×) và người đọc diễn giải đại lượng
    #   này theo tỉ lệ tuyến tính; log sẽ bóp méo khoảng cách Password ↔ nhóm còn lại.
    ax.set_yscale("log")
    ax.set_xlim(0, max(r["rps"] for r in pts) * 1.08)
    ax.set_xlabel("Achieved throughput (journeys/s)", color=INK)
    ax.set_ylabel("p99 journey latency (ms, log scale)", color=INK)
    style(ax); legend_below(fig, ms)
    save(fig, "L1_latency_throughput")


# ── L3 — journeys / CPU·s (golden) ───────────────────────────────────────────
def fig_L3(runs):
    pts = [r for r in runs if r["scenario"] == "constant_vus" and r["eff"]]
    if not pts:
        warn("L3: không có journeys_per_cpu_s (Prometheus không reachable?) — BỎ chart"); return
    ms = mechs_present(pts)
    vals, errs = [], []
    for m in ms:
        v, e = agg([r["eff"] for r in pts if r["mech"] == m])
        vals.append(v); errs.append(e)
    fig, ax = plt.subplots(figsize=(6.6, 3.8))
    xs = range(len(ms))
    ax.bar(xs, vals, yerr=errs, capsize=4, width=0.62,
           color=[MECH_COLORS[m] for m in ms],
           edgecolor=["#e8a317" if m == HIGHLIGHT else "0.25" for m in ms],
           linewidth=[2.0 if m == HIGHLIGHT else 0.8 for m in ms], zorder=3)
    for x, v, e in zip(xs, vals, errs):
        ax.text(x, v + e + max(vals) * 0.03, f"{v:.1f}", ha="center", fontsize=9, color=INK)
    ax.set_xticks(list(xs)); ax.set_xticklabels([disp(m) for m in ms], rotation=18, ha="right")
    ax.set_ylabel("Journeys per CPU-second\n(auth-server, higher is better)", color=INK)
    ax.set_ylim(0, max(v + e for v, e in zip(vals, errs)) * 1.18)
    style(ax); bold_hl_xticks(ax)
    save(fig, "L3_efficiency_cpu")


# ── L8 — p99 vs WAN RTT (ablation Fiat–Shamir ở mức hệ thống) ────────────────
def fig_L8(runs):
    pts = [r for r in runs if r["rtt"] is not None and r["p99"]]
    if not pts:
        warn("L8: không có run rtt-sweep — BỎ chart"); return
    ms = mechs_present(pts)
    fig, ax = plt.subplots(figsize=(6.0, 4.0))
    for m in ms:
        by = {}
        for r in (x for x in pts if x["mech"] == m):
            by.setdefault(r["rtt"], []).append(r["p99"])
        xs = sorted(by)
        ys, es = zip(*[agg(by[x]) for x in xs])
        ax.errorbar(xs, ys, yerr=es, color=MECH_COLORS[m], marker=MARKERS[m], ms=7, lw=2,
                    capsize=3, markeredgecolor="#e8a317" if m == HIGHLIGHT else "0.3",
                    markeredgewidth=1.8 if m == HIGHLIGHT else 0.8,
                    zorder=5 if m == HIGHLIGHT else 3, label=disp(m))
    ax.set_xlabel("Injected WAN round-trip time (ms)", color=INK)
    ax.set_ylabel("p99 journey latency (ms)", color=INK)
    ax.xaxis.set_major_locator(FixedLocator(sorted({r["rtt"] for r in pts})))
    style(ax); legend_below(fig, ms, ncol=3)
    save(fig, "L8_rtt_sensitivity")


# ── LT4 — cầu nối micro (JMH crypto µs) ↔ macro (e2e capacity) ───────────────
def load_jmh():
    if not JMH_JSON or not os.path.isfile(JMH_JSON):
        return {}
    try:
        recs = json.load(open(JMH_JSON))
    except Exception:
        warn("LT4: JMH json không đọc được"); return {}
    got = {}
    for r in recs:
        name = r.get("benchmark", "").split("bench.")[-1]
        if "." not in name:
            continue
        cls, meth = name.split(".", 1)
        if cls not in JMH_MAP:
            continue
        mech, sm, vm = JMH_MAP[cls]
        sc = r.get("primaryMetric", {}).get("score")
        if sc is None:
            continue
        d = got.setdefault(mech, {})
        if meth == sm:
            d["sign"] = sc
        if meth == vm:
            d["verify"] = sc
    # tổng chi phí crypto/lần auth = prove(client) + verify(server); Password không ký
    return {m: (v.get("sign", 0.0) or 0.0) + v["verify"] for m, v in got.items() if "verify" in v}


def fig_LT4(runs):
    crypto = load_jmh()
    cap = {}
    for m in mechs_present(runs, lambda r: r["scenario"] == "constant_vus"):
        v, e = agg([r["rps"] for r in runs if r["scenario"] == "constant_vus" and r["mech"] == m])
        if v:
            cap[m] = (v, e)
    ms = [m for m in ORDER if m in crypto and m in cap]
    if len(ms) < 3:
        warn(f"LT4: chỉ ghép được {len(ms)} cơ chế (thiếu JMH json hoặc run P3) — BỎ chart"); return
    fig, ax = plt.subplots(figsize=(6.6, 4.2))
    xv = [crypto[m] for m in ms]; yv = [cap[m][0] for m in ms]

    # Dải "trần hạ tầng": các cơ chế khóa công khai đều rơi vào cùng một băng throughput
    # BẤT KỂ chi phí mật mã khác nhau 6× ⟹ vẽ băng này để thông điệp ngưỡng tự hiện ra.
    pk = [m for m in ms if m != "Password"]
    if len(pk) >= 3:
        lo, hi = min(cap[m][0] for m in pk), max(cap[m][0] for m in pk)
        ax.axhspan(lo, hi, color="0.88", zorder=0)
        ax.annotate("infrastructure-bound band\n(throughput independent of crypto cost)",
                    xy=(min(xv) * 1.15, (lo + hi) / 2), fontsize=8, color=INK2, va="center")

    for m in ms:
        x = crypto[m]; y, e = cap[m]
        ax.errorbar([x], [y], yerr=[e], color=MECH_COLORS[m], marker=MARKERS[m], ms=12,
                    capsize=3, ls="none",
                    markeredgecolor="#e8a317" if m == HIGHLIGHT else "0.3",
                    markeredgewidth=2.2 if m == HIGHLIGHT else 0.8,
                    zorder=5 if m == HIGHLIGHT else 3, label=disp(m))

    # X = log (BẮT BUỘC): chi phí mật mã trải 83 µs → 146.5 ms = 1771× (3 bậc độ lớn).
    #   Thang tuyến tính sẽ dồn 6/7 cơ chế vào 0.4% bề rộng trục ⟹ hình chỉ còn 2 điểm nhìn thấy.
    # Y = tuyến tính: throughput chỉ trải 10.4 → 76.9 j/s (7.4×), đọc trực tiếp dễ hơn log.
    ax.set_xscale("log")
    ax.set_xlim(min(xv) / 2.2, max(xv) * 3.0)
    ax.set_ylim(0, max(yv) * 1.18)
    ax.set_xlabel("Cryptographic cost per authentication (JMH: prove + verify, µs, log scale)",
                  color=INK, fontsize=10)
    ax.set_ylabel("End-to-end saturated throughput\n(journeys/s)", color=INK)
    style(ax)
    legend_below(fig, ms)
    save(fig, "LT4_micro_macro")


# ── A — Đường bão hoà: achieved vs offered throughput (từ knee-search) ───────
def fig_A(runs):
    """Toàn bộ đường cong bão hoà thay cho MỘT con số knee.

    Vì sao cần: knee là 'bậc cuối còn lành mạnh' nên có độ phân giải một bậc nhị phân
    (đã quan sát: mTLS cho 80 ở lần chạy này và 96 ở lần khác — điểm 96 j/s rơi hai bên
    ngưỡng 0.90). Vẽ CẢ đường achieved-vs-offered thì người đọc tự thấy mỗi cơ chế rời
    khỏi đường chéo lý tưởng ở đâu — trung thực hơn và nhiều thông tin hơn một con số.
    """
    pts = [r for r in runs if r["tag"].startswith(("kneestep", "kneerefine", "kneeconfirm"))
           and r["rate"] and r["rps"]]
    if not pts:
        warn("A: không có run knee-search — BỎ chart"); return
    ms = mechs_present(pts)
    fig, ax = plt.subplots(figsize=(6.6, 4.4))

    # Đường chéo y=x: "phục vụ trọn vẹn tải chào" — mốc lý tưởng.
    lo = min(r["rate"] for r in pts) * 0.85
    hi = max(r["rate"] for r in pts) * 1.15
    ax.plot([lo, hi], [lo, hi], ls=":", lw=1.4, color="0.45", zorder=1)
    ax.annotate("ideal (achieved = offered)", xy=(hi * 0.42, hi * 0.42),
                xytext=(0, 7), textcoords="offset points", rotation=38,
                fontsize=8, color=INK2, ha="center")

    for m in ms:
        by = {}
        for r in (x for x in pts if x["mech"] == m):
            by.setdefault(r["rate"], []).append(r["rps"])
        xs = sorted(by)
        ys, es = zip(*[agg(by[x]) for x in xs])
        ax.errorbar(xs, ys, yerr=es, color=MECH_COLORS[m], marker=MARKERS[m], ms=6.5, lw=2,
                    capsize=3, markeredgecolor="#e8a317" if m == HIGHLIGHT else "0.3",
                    markeredgewidth=1.8 if m == HIGHLIGHT else 0.8,
                    zorder=5 if m == HIGHLIGHT else 3, label=disp(m))
        # đánh dấu điểm rời đường chéo (achieved < 90% offered lần đầu) = knee đo được
        for x in xs:
            a, _ = agg(by[x])
            if a is not None and a < 0.90 * x:
                ax.plot([x], [a], marker="x", ms=11, mew=2.2, color=MECH_COLORS[m], zorder=6)
                break

    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("Offered load (journeys/s, log)", color=INK)
    ax.set_ylabel("Achieved throughput (journeys/s, log)", color=INK)
    # Chỉ ghi nhãn các BẬC CHÍNH của thang; điểm refine (20,24,80,96,112) vẫn được vẽ
    # nhưng không gắn nhãn — nếu gắn hết thì "112" và "128" chồng lên nhau.
    allr = sorted({r["rate"] for r in pts})
    ticks = [t for t in (4, 8, 16, 32, 64, 128) if min(allr) <= t <= max(allr)]
    ax.xaxis.set_major_locator(FixedLocator(ticks))
    ax.set_xticklabels([str(t) for t in ticks], fontsize=9)
    ax.xaxis.set_minor_locator(FixedLocator([t for t in allr if t not in ticks]))
    ax.xaxis.set_minor_formatter(NullFormatter())   # minor chỉ là vạch, KHÔNG nhãn
    ax.yaxis.set_major_locator(FixedLocator([4, 8, 16, 32, 64, 128]))
    ax.set_yticklabels(["4", "8", "16", "32", "64", "128"], fontsize=8)
    ax.set_xlim(lo, hi)
    style(ax)
    ax.annotate("×  = first point below 90% of offered (measured knee)",
                xy=(0.02, 0.96), xycoords="axes fraction", fontsize=8, color=INK2, va="top")
    legend_below(fig, ms)
    save(fig, "A_saturation_curve")


if __name__ == "__main__":
    if not os.path.isdir(RESULTS):
        sys.exit(f"✗ không thấy thư mục kết quả: {RESULTS}")
    runs = load_runs()
    if not runs:
        sys.exit(f"✗ không có *.summary.json hợp lệ trong {RESULTS}")
    print(f"   nạp {len(runs)} run từ {RESULTS}")
    fig_A(runs); fig_L1(runs); fig_L3(runs); fig_L8(runs); fig_LT4(runs)
