package com.openbanking.psu.auth.spi.crypto.mldsa;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * Verify <b>ML-DSA-65 (FIPS 204)</b> bằng <b>liboqs NATIVE</b> (Open Quantum Safe) qua Panama FFM —
 * lattice NTT chạy off-heap (AVX2), KHÔNG tạo rác mảng đa thức trên JVM heap (giải bài toán GC của
 * payload KB-scale). Tương ứng vai trò libsodium-native của NIPoK ⟹ A/B "realistic all-native".
 *
 * <p>OQS API: {@code OQS_SIG* OQS_SIG_new("ML-DSA-65")} → {@code OQS_STATUS OQS_SIG_verify(sig_obj,
 * msg, msg_len, sig, sig_len, public_key)}. {@link #available()} = false nếu thiếu liboqs.so/FFM
 * (môi trường hiện tại) ⟹ {@link MlDsaVerifier} tự fallback SunJCE. STATELESS, THREAD-SAFE.
 *
 * <p><b>Ghi chú trung thực</b>: liboqs.so KHÔNG cài trong cluster hiện tại ⟹ path này được KIẾN TRÚC
 * (sẵn sàng bật khi cài liboqs) nhưng e2e/JMH dùng SunJCE. publicKey rút raw từ X.509 (32B header bỏ).
 */
public final class LiboqsMlDsa {

  private static final int OQS_SUCCESS = 0;
  private static final int PK_LEN = 1952;   // ML-DSA-65 raw public key

  private final MethodHandle hVerify;
  private final MemorySegment sigObj;       // OQS_SIG* (toàn cục, tái dùng)
  private final boolean ok;

  public LiboqsMlDsa() {
    MethodHandle vVerify = null;
    MemorySegment obj = MemorySegment.NULL;
    boolean available = false;
    try {
      Linker linker = Linker.nativeLinker();
      SymbolLookup so = lookup();
      if (so != null) {
        MethodHandle vNew = linker.downcallHandle(so.find("OQS_SIG_new").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        vVerify = linker.downcallHandle(so.find("OQS_SIG_verify").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
        MemorySegment alg = Arena.global().allocateFrom("ML-DSA-65");
        obj = (MemorySegment) vNew.invoke(alg);
        available = !obj.equals(MemorySegment.NULL);
      }
    } catch (Throwable t) {
      available = false;
    }
    this.hVerify = vVerify;
    this.sigObj = obj;
    this.ok = available;
  }

  public boolean available() {
    return ok;
  }

  /** Verify ML-DSA-65. Rút raw public key (1952B) từ X.509 SubjectPublicKeyInfo (đuôi). */
  public boolean verify(PublicKey x509Pub, byte[] message, byte[] signature) {
    if (!ok) {
      return false;
    }
    byte[] enc = x509Pub.getEncoded();
    if (enc.length < PK_LEN) {
      return false;
    }
    byte[] rawPk = new byte[PK_LEN];
    System.arraycopy(enc, enc.length - PK_LEN, rawPk, 0, PK_LEN);   // raw key = đuôi SPKI
    try (Arena a = Arena.ofConfined()) {
      MemorySegment m = seg(a, message);
      MemorySegment sig = seg(a, signature);
      MemorySegment pk = seg(a, rawPk);
      int rc = (int) hVerify.invoke(sigObj, m, (long) message.length, sig, (long) signature.length, pk);
      return rc == OQS_SUCCESS;
    } catch (Throwable t) {
      return false;
    }
  }

  private static MemorySegment seg(Arena a, byte[] b) {
    MemorySegment m = a.allocate(Math.max(1, b.length));
    MemorySegment.copy(b, 0, m, ValueLayout.JAVA_BYTE, 0, b.length);
    return m;
  }

  private static SymbolLookup lookup() {
    List<String> c = new ArrayList<>();
    String env = System.getenv("LIBOQS_PATH");
    if (env != null && !env.isBlank()) c.add(env);
    c.add("oqs"); c.add("liboqs.so"); c.add("liboqs.so.0.12.0"); c.add("liboqs.so.7");
    c.add("/usr/local/lib/liboqs.so"); c.add("/usr/lib/x86_64-linux-gnu/liboqs.so");
    c.add("liboqs.dylib");
    for (String name : c) {
      try {
        return SymbolLookup.libraryLookup(name, Arena.global());
      } catch (Throwable ignore) { /* next */ }
    }
    return null;
  }
}
