#!/usr/bin/env python3
"""
bench_handshake_load.py - Saturating TLS handshake load generator (in-process, multi-threaded).

Each connection = 1 NEW full handshake (session tickets disabled -> the server MUST sign CertificateVerify
every time) -> the server (Envoy) runs the signing crypto continuously. The SNI is sent so that Envoy selects the right certificate.
The chain is NOT verified (the handshake rate is measured, not trust).

In ra JSON: {"handshakes", "seconds", "rate", "workers", "sni"}

Usage:
  python3 bench_handshake_load.py --sni bank.openbanking.dev --port 18443 --duration 8 --workers 16
"""
import argparse
import json
import socket
import ssl
import threading
import time


def make_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.options |= ssl.OP_NO_TICKET            # resumption disabled -> full handshake every time
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3   # matches the Gateway minProtocolVersion
    except Exception:
        pass
    return ctx


def worker(host, port, sni, deadline, counter, idx):
    ctx = make_ctx()
    n = 0
    while time.monotonic() < deadline:
        try:
            raw = socket.create_connection((host, port), timeout=5)
            s = ctx.wrap_socket(raw, server_hostname=sni)
            s.close()
            n += 1
        except Exception:
            pass
    counter[idx] = n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18443)
    ap.add_argument("--sni", required=True)
    ap.add_argument("--duration", type=float, default=8.0)
    ap.add_argument("--workers", type=int, default=16)
    a = ap.parse_args()

    counter = [0] * a.workers
    t0 = time.monotonic()
    deadline = t0 + a.duration
    threads = [threading.Thread(target=worker, args=(a.host, a.port, a.sni, deadline, counter, i))
               for i in range(a.workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    dt = time.monotonic() - t0
    total = sum(counter)
    print(json.dumps({"handshakes": total, "seconds": round(dt, 3),
                      "rate": round(total / dt, 1) if dt > 0 else 0,
                      "workers": a.workers, "sni": a.sni}))


if __name__ == "__main__":
    main()
