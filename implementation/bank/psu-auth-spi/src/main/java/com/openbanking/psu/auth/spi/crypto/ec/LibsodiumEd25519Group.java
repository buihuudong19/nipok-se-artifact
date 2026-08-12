package com.openbanking.psu.auth.spi.crypto.ec;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Impl đại số NIPoK trên <b>libsodium NATIVE</b> qua Panama FFM (java.lang.foreign, JDK 22+).
 *
 * <p><b>Mục đích — CÔNG BẰNG REALISTIC</b>: NIPoK không dùng được BoringSSL (không phơi bày raw
 * double-scalar-mul cho Schnorr tùy biến), nên backend này cho NIPoK chạy NATIVE để so all-native với
 * mTLS/JWT (BoringSSL). Đánh đổi: KHÔNG có double-scalar-mul gộp ⟹ làm 2 scalar-mult rời
 * ({@code sB}, {@code eX}) + 1 point-add (mất Straus) — đây là chi phí THẬT của primitive phi-chuẩn.
 *
 * <p><b>Tương thích nhị phân với {@link ElisabethEd25519Group}</b>: hash {@code e} length-prefixed HỆT
 * (SHA-512 + reduce mod ℓ), scalar/point cùng encoding (32B nén, scalar mod ℓ) ⟹ proof do elisabeth
 * sinh verify được trên libsodium và ngược lại (test interop chứng minh).
 *
 * <p>THREAD-SAFE: MethodHandle bất biến; mỗi op dùng {@link Arena#ofConfined} riêng-luồng; SHA-512
 * tái dùng ThreadLocal. {@link #available()} = false nếu thiếu libsodium.so/FFM → registry fallback.
 */
public final class LibsodiumEd25519Group implements Ed25519Group {

  private static final int P = 32, S = 32, H = 64;   // point, scalar, hash(SHA-512)

  private final SecureRandom rng = new SecureRandom();
  private final String shaProvider;
  private final ThreadLocal<MessageDigest> sha512 = ThreadLocal.withInitial(this::newSha512);

  // libsodium handles (null nếu không khả dụng)
  private final MethodHandle hBaseNoclamp;   // crypto_scalarmult_ed25519_base_noclamp(q, n) → q=nB
  private final MethodHandle hNoclamp;       // crypto_scalarmult_ed25519_noclamp(q, n, p)   → q=nP
  private final MethodHandle hAdd;           // crypto_core_ed25519_add(r, p, q)             → r=p+q
  private final MethodHandle hScalarMul;     // crypto_core_ed25519_scalar_mul(z, x, y)      → z=xy mod ℓ
  private final MethodHandle hScalarSub;     // crypto_core_ed25519_scalar_sub(z, x, y)      → z=x−y mod ℓ
  private final MethodHandle hScalarReduce;  // crypto_core_ed25519_scalar_reduce(r, s[64])  → r=s mod ℓ
  private final MethodHandle hIsValid;       // crypto_core_ed25519_is_valid_point(p) → 1 hợp lệ
  private final boolean ok;

  public LibsodiumEd25519Group(String shaProvider) {
    this.shaProvider = (shaProvider == null || shaProvider.isBlank()) ? null : shaProvider;
    MethodHandle bn = null, nc = null, add = null, sm = null, ss = null, sr = null, iv = null;
    boolean available = false;
    try {
      Linker linker = Linker.nativeLinker();
      SymbolLookup so = lookup();
      if (so != null) {
        MethodHandle init = linker.downcallHandle(so.find("sodium_init").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT));
        if ((int) init.invoke() >= 0) {
          var addr = ValueLayout.ADDRESS;
          var i32 = ValueLayout.JAVA_INT;
          bn = linker.downcallHandle(so.find("crypto_scalarmult_ed25519_base_noclamp").orElseThrow(),
              FunctionDescriptor.of(i32, addr, addr));
          nc = linker.downcallHandle(so.find("crypto_scalarmult_ed25519_noclamp").orElseThrow(),
              FunctionDescriptor.of(i32, addr, addr, addr));
          add = linker.downcallHandle(so.find("crypto_core_ed25519_add").orElseThrow(),
              FunctionDescriptor.of(i32, addr, addr, addr));
          sm = linker.downcallHandle(so.find("crypto_core_ed25519_scalar_mul").orElseThrow(),
              FunctionDescriptor.ofVoid(addr, addr, addr));
          ss = linker.downcallHandle(so.find("crypto_core_ed25519_scalar_sub").orElseThrow(),
              FunctionDescriptor.ofVoid(addr, addr, addr));
          sr = linker.downcallHandle(so.find("crypto_core_ed25519_scalar_reduce").orElseThrow(),
              FunctionDescriptor.ofVoid(addr, addr));
          iv = linker.downcallHandle(so.find("crypto_core_ed25519_is_valid_point").orElseThrow(),
              FunctionDescriptor.of(i32, addr));
          available = true;
        }
      }
    } catch (Throwable t) {
      // libsodium thiếu / FFM bị chặn → ok=false
    }
    this.hBaseNoclamp = bn; this.hNoclamp = nc; this.hAdd = add;
    this.hScalarMul = sm; this.hScalarSub = ss; this.hScalarReduce = sr; this.hIsValid = iv;
    this.ok = available;
  }

  public boolean available() { return ok; }

  @Override
  public byte[] randomScalar() {
    byte[] wide = new byte[H];
    rng.nextBytes(wide);
    return reduce(wide);                       // 64B → mod ℓ (native)
  }

  @Override
  public byte[] scalarMultBase(byte[] scalar) {
    try (Arena a = Arena.ofConfined()) {
      MemorySegment q = a.allocate(P);
      hBaseNoclamp.invoke(q, seg(a, scalar));  // q = scalar·B  (scalar < ℓ ⟹ == [scalar mod ℓ]B)
      return q.toArray(ValueLayout.JAVA_BYTE);
    } catch (Throwable t) {
      throw new IllegalStateException("libsodium scalarMultBase lỗi", t);
    }
  }

  @Override
  public byte[] scalarSubMul(byte[] v, byte[] e, byte[] x) {
    try (Arena a = Arena.ofConfined()) {
      MemorySegment ex = a.allocate(S);
      hScalarMul.invoke(ex, seg(a, e), seg(a, x));         // ex = e·x mod ℓ
      MemorySegment z = a.allocate(S);
      hScalarSub.invoke(z, seg(a, v), ex);                 // z = v − ex mod ℓ
      return z.toArray(ValueLayout.JAVA_BYTE);
    } catch (Throwable t) {
      throw new IllegalStateException("libsodium scalarSubMul lỗi", t);
    }
  }

  @Override
  public byte[] hashToScalar(byte[]... chunks) {
    MessageDigest md = sha512.get();
    md.reset();
    for (byte[] c : chunks) {                              // length-prefix HỆT ElisabethEd25519Group
      int n = c.length;
      md.update((byte) (n >>> 24)); md.update((byte) (n >>> 16));
      md.update((byte) (n >>> 8)); md.update((byte) n);
      md.update(c);
    }
    return reduce(md.digest());                            // SHA-512(64B) mod ℓ (native reduce)
  }

  @Override
  public boolean verifySchnorr(byte[] X, byte[] V, byte[] s, byte[] e) {
    try (Arena a = Arena.ofConfined()) {
      MemorySegment xp = seg(a, X);
      if ((int) hIsValid.invoke(xp) != 1) {
        return false;                                      // small-order/identity/không-canonical → loại
      }
      MemorySegment sB = a.allocate(P);
      MemorySegment eX = a.allocate(P);
      MemorySegment sum = a.allocate(P);
      if ((int) hBaseNoclamp.invoke(sB, seg(a, s)) != 0) return false;   // sB = s·B
      if ((int) hNoclamp.invoke(eX, seg(a, e), xp) != 0) return false;   // eX = e·X
      if ((int) hAdd.invoke(sum, sB, eX) != 0) return false;            // sum = sB + eX
      return MessageDigest.isEqual(sum.toArray(ValueLayout.JAVA_BYTE), V);
    } catch (Throwable t) {
      return false;
    }
  }

  @Override
  public boolean isValidPublicPoint(byte[] X) {
    try (Arena a = Arena.ofConfined()) {
      return (int) hIsValid.invoke(seg(a, X)) == 1;
    } catch (Throwable t) {
      return false;
    }
  }

  // ── helpers ─────────────────────────────────────────────────────────────
  private byte[] reduce(byte[] wide64) {
    try (Arena a = Arena.ofConfined()) {
      MemorySegment r = a.allocate(S);
      hScalarReduce.invoke(r, seg(a, wide64));
      return r.toArray(ValueLayout.JAVA_BYTE);
    } catch (Throwable t) {
      throw new IllegalStateException("libsodium scalar_reduce lỗi", t);
    }
  }

  private static MemorySegment seg(Arena a, byte[] b) {
    MemorySegment m = a.allocate(b.length);
    MemorySegment.copy(b, 0, m, ValueLayout.JAVA_BYTE, 0, b.length);
    return m;
  }

  private MessageDigest newSha512() {
    try {
      return shaProvider == null ? MessageDigest.getInstance("SHA-512")
          : MessageDigest.getInstance("SHA-512", shaProvider);
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      try {
        return MessageDigest.getInstance("SHA-512");
      } catch (NoSuchAlgorithmException e2) {
        throw new IllegalStateException("SHA-512 không khả dụng", e2);
      }
    }
  }

  private static SymbolLookup lookup() {
    List<String> c = new ArrayList<>();
    String env = System.getenv("LIBSODIUM_PATH");
    if (env != null && !env.isBlank()) c.add(env);
    c.add("sodium"); c.add("libsodium.so"); c.add("libsodium.so.23");
    c.add("/lib/x86_64-linux-gnu/libsodium.so.23");
    c.add("/usr/lib/x86_64-linux-gnu/libsodium.so.23");
    c.add("/usr/local/lib/libsodium.so"); c.add("libsodium.dylib");
    for (String name : c) {
      try {
        return SymbolLookup.libraryLookup(name, Arena.global());
      } catch (Throwable ignore) { /* next */ }
    }
    return null;
  }
}
