package com.openbanking.psu.auth.spi.crypto.schnorr;

import java.util.Arrays;

import com.openbanking.psu.auth.spi.crypto.ec.Ed25519Group;

/**
 * CLIENT-side wallet (customer-agent) of the INTERACTIVE Schnorr sigma protocol - custody of the secret scalar {@code x},
 * INDEPENDENT of NIPoK ({@code SimulatorWalletProvider}). Because the protocol has 3 passes, the nonce {@code v} must LIVE
 * between pass 1 (commit) and pass 3 (respond) => it is returned in a {@link Commitment} (NOT kept in the wallet state
 * => THREAD-SAFE, several concurrent sessions supported).
 *
 * <ul>
 *   <li>{@link #commit()} - pass 1: {@code v <- Z_l; R = v*G}; returns {@code (v, R)}.</li>
 *   <li>{@link #respond(Commitment, byte[])} - pass-3: {@code s = v − e·x mod ℓ}.</li>
 * </ul>
 *
 * <p>STRIDE information disclosure: {@code v} from a CSPRNG for EVERY session (reusing {@code v} reveals {@code x}); the agent zeroises {@code v}
 * right after respond. {@code x} is resident (own custody), zeroised at {@link #close()}.
 */
public final class SchnorrInteractiveWallet implements AutoCloseable {

  private final Ed25519Group ec;
  private final byte[] x;            // private scalar (own custody, independent of NIPoK)
  private final byte[] publicY;      // Y = x·G

  public SchnorrInteractiveWallet(byte[] privateScalar, Ed25519Group ec) {
    this.ec = ec;
    this.x = privateScalar.clone();
    this.publicY = ec.scalarMultBase(privateScalar);   // Y = x*G (public, computed once)
  }

  /** pass 1: generates the commitment. */
  public Commitment commit() {
    byte[] v = ec.randomScalar();           // ephemeral, NEW for every session
    byte[] r = ec.scalarMultBase(v);        // R = v·G
    return new Commitment(v, r);
  }

  /** Pass 3: computes the response from the server challenge {@code e}. */
  public byte[] respond(Commitment c, byte[] e) {
    return ec.scalarSubMul(c.v(), e, x);    // s = v − e·x
  }

  public byte[] publicPoint() {
    return publicY.clone();
  }

  @Override
  public void close() {
    Arrays.fill(x, (byte) 0);               // x zeroised at shutdown
  }

  /** Client session state between pass 1 and pass 3 (secret {@code v} + public {@code R}). */
  public record Commitment(byte[] v, byte[] R) {
    public void zeroize() {
      Arrays.fill(v, (byte) 0);             // called by the agent after respond (protects x)
    }
  }
}
