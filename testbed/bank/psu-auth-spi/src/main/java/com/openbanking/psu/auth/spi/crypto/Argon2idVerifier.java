package com.openbanking.psu.auth.spi.crypto;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import com.openbanking.psu.auth.spi.AuthMethod;
import com.openbanking.psu.auth.spi.CredentialVerifier;
import com.openbanking.psu.auth.spi.model.Challenge;
import com.openbanking.psu.auth.spi.model.PasswordHash;
import com.openbanking.psu.auth.spi.model.PasswordInput;
import com.openbanking.psu.auth.spi.model.VerificationResult;

/**
 * PASSWORD verifier (Argon2id + pepper). PURE and THREAD-SAFE (reads only the immutable {@code params}/{@code pepper}
 * and creates local state at every call -> no lock).
 *
 * <p><b>Pepper</b> (STRIDE information disclosure): {@code preimage = HMAC-SHA256(pepper, UTF8(password))} BEFORE Argon2id.
 * The pepper is a server secret (HSM/secret), NOT in the PHC/database => a database leak still cannot be cracked offline.
 * <p><b>PHC</b>: {@code $argon2id$v=19$m=..,t=..,p=..$saltB64$hashB64} (embedded per-user salt).
 * <p><b>verify</b>: uses exactly the parameters read FROM the PHC (supports parameter rotation); constant-time comparison.
 */
public final class Argon2idVerifier implements CredentialVerifier<PasswordHash, PasswordInput> {

  private static final SecureRandom RNG = new SecureRandom();
  private static final Base64.Encoder B64 = Base64.getEncoder().withoutPadding();
  private static final Base64.Decoder B64D = Base64.getDecoder();

  private final Argon2Params params;   // used when HASHING (registration)
  private final byte[] pepper;         // immutable copy

  public Argon2idVerifier(Argon2Params params, byte[] pepper) {
    this.params = params;
    this.pepper = (pepper == null) ? new byte[0] : pepper.clone();
  }

  @Override public AuthMethod method() { return AuthMethod.PASSWORD; }
  @Override public boolean requiresChallenge() { return false; }

  /** Registration: hashes the password -> PHC string stored in the database. */
  public String hash(char[] password) {
    byte[] pre = pepperPreimage(password);
    byte[] salt = new byte[params.saltLength()];
    RNG.nextBytes(salt);
    byte[] raw = argon2(pre, salt, params.memoryKib(), params.iterations(), params.parallelism(), params.hashLength());
    Arrays.fill(pre, (byte) 0);
    String phc = "$argon2id$v=19$m=" + params.memoryKib() + ",t=" + params.iterations()
        + ",p=" + params.parallelism() + "$" + B64.encodeToString(salt) + "$" + B64.encodeToString(raw);
    Arrays.fill(raw, (byte) 0);
    return phc;
  }

  /** Login: recomputes with the parameters of the PHC, constant-time comparison. */
  @Override
  public VerificationResult verify(PasswordHash stored, PasswordInput presented, Challenge challenge) {
    byte[] pre = pepperPreimage(presented.password());
    try {
      Phc p = Phc.parse(stored.phc());
      byte[] candidate = argon2(pre, p.salt, p.mem, p.iter, p.par, p.hash.length);
      boolean ok = MessageDigest.isEqual(candidate, p.hash); // constant-time
      Arrays.fill(candidate, (byte) 0);
      return ok ? VerificationResult.success() : VerificationResult.fail("password_mismatch");
    } catch (RuntimeException e) {
      return VerificationResult.fail("bad_phc");
    } finally {
      Arrays.fill(pre, (byte) 0);
    }
  }

  // -- helpers ---------------------------------------------------------------
  private byte[] pepperPreimage(char[] password) {
    byte[] pw = utf8(password);
    if (pepper.length == 0) {
      return pw;
    }
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(pepper, "HmacSHA256"));
      byte[] out = mac.doFinal(pw);
      Arrays.fill(pw, (byte) 0);
      return out;
    } catch (Exception e) {
      throw new IllegalStateException("pepper HMAC failed", e);
    }
  }

  private static byte[] argon2(byte[] input, byte[] salt, int memKib, int iter, int par, int hashLen) {
    Argon2Parameters ap = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
        .withVersion(Argon2Parameters.ARGON2_VERSION_13)
        .withMemoryAsKB(memKib).withIterations(iter).withParallelism(par).withSalt(salt).build();
    Argon2BytesGenerator gen = new Argon2BytesGenerator();
    gen.init(ap);
    byte[] out = new byte[hashLen];
    gen.generateBytes(input, out);
    return out;
  }

  private static byte[] utf8(char[] c) {
    ByteBuffer bb = StandardCharsets.UTF_8.encode(CharBuffer.wrap(c));
    byte[] b = new byte[bb.remaining()];
    bb.get(b);
    return b;
  }

  private record Phc(int mem, int iter, int par, byte[] salt, byte[] hash) {
    static Phc parse(String phc) {
      String[] s = phc.split("\\$"); // ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
      if (s.length != 6 || !"argon2id".equals(s[1])) {
        throw new IllegalArgumentException("invalid PHC");
      }
      int mem = 0, iter = 0, par = 0;
      for (String kv : s[3].split(",")) {
        String[] p = kv.split("=");
        switch (p[0]) {
          case "m" -> mem = Integer.parseInt(p[1]);
          case "t" -> iter = Integer.parseInt(p[1]);
          case "p" -> par = Integer.parseInt(p[1]);
          default -> { /* ignore */ }
        }
      }
      return new Phc(mem, iter, par, B64D.decode(s[4]), B64D.decode(s[5]));
    }
  }
}
