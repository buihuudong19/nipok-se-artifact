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
 * <b>Ed25519 (RFC 8032)</b> verification with <b>NATIVE libsodium</b> ({@code crypto_sign_verify_detached})
 * through Panama FFM - native fused double-scalar multiplication (optimised for STANDARD signatures; not available for the non-standard NIPoK).
 *
 * <p>Lets Pure-EdDSA verify on the same backend matrix {elisabeth, Conscrypt, libsodium} as JWT.
 * {@link #available()} = false without libsodium.so/FFM. STATELESS, THREAD-SAFE (arena confined per call).
 */
public final class LibsodiumEd25519Verifier {

  private static final int PK = 32, SIG = 64;

  private final MethodHandle hVerify;
  private final boolean ok;

  public LibsodiumEd25519Verifier() {
    MethodHandle v = null;
    boolean available = false;
    try {
      Linker linker = Linker.nativeLinker();
      SymbolLookup so = lookup();
      if (so != null) {
        MethodHandle init = linker.downcallHandle(so.find("sodium_init").orElseThrow(),
            FunctionDescriptor.of(ValueLayout.JAVA_INT));
        if ((int) init.invoke() >= 0) {
          v = linker.downcallHandle(so.find("crypto_sign_verify_detached").orElseThrow(),
              FunctionDescriptor.of(ValueLayout.JAVA_INT,
                  ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
          available = true;
        }
      }
    } catch (Throwable t) {
      // libsodium missing -> ok=false
    }
    this.hVerify = v;
    this.ok = available;
  }

  public boolean available() {
    return ok;
  }

  /** @return true if the signature is valid. publicKeyA 32 bytes, signature 64 bytes. */
  public boolean verify(byte[] publicKeyA, byte[] message, byte[] signature) {
    if (!ok || publicKeyA == null || publicKeyA.length != PK || signature == null || signature.length != SIG) {
      return false;
    }
    try (Arena a = Arena.ofConfined()) {
      MemorySegment sig = seg(a, signature);
      MemorySegment m = a.allocate(Math.max(1, message.length));
      MemorySegment.copy(message, 0, m, ValueLayout.JAVA_BYTE, 0, message.length);
      MemorySegment pk = seg(a, publicKeyA);
      return (int) hVerify.invoke(sig, m, (long) message.length, pk) == 0;
    } catch (Throwable t) {
      return false;
    }
  }

  private static MemorySegment seg(Arena a, byte[] b) {
    MemorySegment m = a.allocate(b.length);
    MemorySegment.copy(b, 0, m, ValueLayout.JAVA_BYTE, 0, b.length);
    return m;
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
