package com.openbanking.psu.auth.spi.crypto.ed25519;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.util.ArrayList;
import java.util.List;

/**
 * Ký <b>Ed25519 (RFC 8032)</b> bằng <b>libsodium NATIVE</b> ({@code crypto_sign_detached}) qua Panama
 * FFM — để phía agent của Private-Key-JWT ký NATIVE, đồng nhất phép đo với NIPoK prove-native.
 *
 * <p>Khác NIPoK prove (raw scalar-mult tùy biến), JWT sign là chữ ký Ed25519 CHUẨN ⟹ dùng được hàm
 * native đã tối ưu trọn gói {@code crypto_sign_detached} (key-schedule + nonce + R + S). Chữ ký HỢP LỆ
 * với mọi verifier RFC 8032 (chứng minh bằng test: libsodium sign → SunEC verify == true).
 *
 * <p>STATEFUL nhẹ: dẫn xuất secret-key {@code sk[64]} từ seed MỘT lần (constructor) vào shared Arena →
 * mỗi {@link #sign} chỉ tốn 1 native sign. THREAD-SAFE (crypto_sign_detached reentrant; arena confined
 * per-call cho buffer message/sig). {@link #available()} = false nếu thiếu libsodium.so/FFM.
 */
public final class LibsodiumEd25519Signer {

  private static final int SEED = 32, PK = 32, SK = 64, SIG = 64;

  private final MethodHandle hSeedKeypair, hSignDetached;
  private final Arena persistent;
  private final MemorySegment sk;     // secret-key dẫn xuất từ seed (shared arena)
  private final boolean ok;

  public LibsodiumEd25519Signer(byte[] seed32) {
    if (seed32 == null || seed32.length != SEED) {
      throw new IllegalArgumentException("Ed25519 seed phải 32 byte");
    }
    MethodHandle hSeed = null, hSign = null;
    Arena arena = null;
    MemorySegment skSeg = null;
    boolean available = false;
    try {
      Linker linker = Linker.nativeLinker();
      SymbolLookup so = lookup();
      if (so != null) {
        MethodHandle init = linker.downcallHandle(so.find("sodium_init").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT));
        if ((int) init.invoke() >= 0) {
          var addr = ValueLayout.ADDRESS;
          hSeed = linker.downcallHandle(so.find("crypto_sign_seed_keypair").orElseThrow(),
              FunctionDescriptor.of(ValueLayout.JAVA_INT, addr, addr, addr));
          hSign = linker.downcallHandle(so.find("crypto_sign_detached").orElseThrow(),
              FunctionDescriptor.of(ValueLayout.JAVA_INT, addr, addr, addr, ValueLayout.JAVA_LONG, addr));
          arena = Arena.ofShared();
          skSeg = arena.allocate(SK);
          try (Arena tmp = Arena.ofConfined()) {
            MemorySegment seedSeg = tmp.allocate(SEED);
            MemorySegment.copy(seed32, 0, seedSeg, ValueLayout.JAVA_BYTE, 0, SEED);
            MemorySegment pkScratch = tmp.allocate(PK);
            if ((int) hSeed.invoke(pkScratch, skSeg, seedSeg) == 0) {
              available = true;
            }
          }
        }
      }
    } catch (Throwable t) {
      // libsodium thiếu / FFM chặn → ok=false
    }
    this.hSeedKeypair = hSeed;
    this.hSignDetached = hSign;
    this.persistent = arena;
    this.sk = skSeg;
    this.ok = available;
  }

  public boolean available() {
    return ok;
  }

  /** Ký message → 64B chữ ký Ed25519 (R‖S). */
  public byte[] sign(byte[] message) {
    if (!ok) {
      throw new IllegalStateException("libsodium signer không khả dụng");
    }
    try (Arena a = Arena.ofConfined()) {
      MemorySegment m = a.allocate(Math.max(1, message.length));
      MemorySegment.copy(message, 0, m, ValueLayout.JAVA_BYTE, 0, message.length);
      MemorySegment sig = a.allocate(SIG);
      int rc = (int) hSignDetached.invoke(sig, MemorySegment.NULL, m, (long) message.length, sk);
      if (rc != 0) {
        throw new IllegalStateException("crypto_sign_detached rc=" + rc);
      }
      return sig.toArray(ValueLayout.JAVA_BYTE);
    } catch (RuntimeException e) {
      throw e;
    } catch (Throwable t) {
      throw new IllegalStateException("libsodium sign lỗi", t);
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
