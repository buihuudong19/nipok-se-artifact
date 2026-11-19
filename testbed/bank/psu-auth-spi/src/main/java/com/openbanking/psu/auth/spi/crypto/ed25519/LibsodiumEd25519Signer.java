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
 * <b>Ed25519 (RFC 8032)</b> signing with <b>NATIVE libsodium</b> ({@code crypto_sign_detached}) through Panama
 * FFM - lets the agent side of Private-Key-JWT sign NATIVELY, consistent with the native NIPoK prove measurement.
 *
 * <p>Unlike the NIPoK prove (custom raw scalar multiplication), a JWT signature is a STANDARD Ed25519 signature => the
 * fully optimised native function {@code crypto_sign_detached} can be used (key schedule + nonce + R + S). The signatures
 * are VALID for every RFC 8032 verifier (shown by a test: libsodium sign -> SunEC verify == true).
 *
 * <p>Lightly STATEFUL: the secret key {@code sk[64]} is derived from the seed ONCE (constructor) into a shared Arena ->
 * every {@link #sign} costs only 1 native signature. THREAD-SAFE (crypto_sign_detached is reentrant; a per-call confined
 * arena holds the message/signature buffers). {@link #available()} = false without libsodium.so/FFM.
 */
public final class LibsodiumEd25519Signer {

  private static final int SEED = 32, PK = 32, SK = 64, SIG = 64;

  private final MethodHandle hSeedKeypair, hSignDetached;
  private final Arena persistent;
  private final MemorySegment sk;     // secret key derived from the seed (shared arena)
  private final boolean ok;

  public LibsodiumEd25519Signer(byte[] seed32) {
    if (seed32 == null || seed32.length != SEED) {
      throw new IllegalArgumentException("Ed25519 seed must be 32 bytes");
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
      // libsodium missing / FFM blocked -> ok=false
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

  /** Signs the message -> 64-byte Ed25519 signature (R||S). */
  public byte[] sign(byte[] message) {
    if (!ok) {
      throw new IllegalStateException("libsodium signer not available");
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
      throw new IllegalStateException("libsodium sign failed", t);
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
