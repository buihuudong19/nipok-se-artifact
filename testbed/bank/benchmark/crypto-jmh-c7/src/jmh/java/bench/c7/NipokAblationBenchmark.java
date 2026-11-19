package bench.c7;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;

import com.openbanking.psu.auth.spi.crypto.ec.Ed25519Group;
import com.openbanking.psu.auth.spi.crypto.ec.ElisabethEd25519Group;
import com.openbanking.psu.auth.spi.crypto.ec.PreparedPoint;
import com.openbanking.psu.auth.spi.crypto.nipok.NipokEncoding;
import com.openbanking.psu.auth.spi.crypto.nipok.NipokEngine;
import com.openbanking.psu.auth.spi.crypto.nipok.NipokVerifier;
import com.openbanking.psu.auth.spi.model.DiscreteLogCredential;
import com.openbanking.psu.auth.spi.model.NipokContext;
import com.openbanking.psu.auth.spi.model.NipokProof;
import com.openbanking.psu.auth.spi.wallet.SimulatorWalletProvider;
import com.openbanking.psu.auth.spi.wallet.SimulatorWalletProvider.CustodyMode;

/**
 * Security-cost ablation (Reviewer 1, Comment 7): CPU cost of every step of one NIPoK authentication, in the end-to-end
 * configuration of the testbed. Measurement-only benchmark; the service code is unchanged.
 *
 * <p><b>Source of every step.</b> The real code of the deployed psu-auth-spi ({@code run-R1C7.sh build} publishes it to
 * mavenLocal): {@link SimulatorWalletProvider#prove} (RESIDENT and SEALED), {@link NipokEngine#challenge},
 * {@link NipokVerifier}, {@link PreparedPoint}, {@link NipokEncoding} (canonical-s check at decoding, key check at
 * registration). Parts that are {@code private} or belong to the auth-server or agent (crypto-jmh-c7 does not depend on
 * these two modules) are copied statement by statement (md5 prefixes of the measured source files in brackets, see
 * docs/provenance.md): {@code SimulatorWalletProvider.unsealGcm()} and {@code deriveNonce()} (b427e1e0...),
 * {@code NipokChallengeStore} (059745f6..., Spring annotations removed), the decoding and comb cache of
 * {@code NipokAuthenticationProvider.authenticate()} (a6d8100c...), {@code ChannelBinding.tlsServerEndPoint()}
 * of the customer-agent (90d0d1ec...). {@link #setup()} runs a correctness gate (the copies must match the real code on
 * the same x and the same proof) before measuring; a failure stops the run.
 *
 * <p><b>Configuration as end to end:</b> elisabeth group; 32-byte cb = SHA-256(DER of the gateway certificate); id_P
 * {@code nipok-1}; id_V {@code bank}. {@code shaProvider=Conscrypt}: SHA-512 of the auth-server
 * ({@code app.psu.nipok.sha-provider}); {@code default}: JCA SHA-512, as in the agent and in the main JMH session of the
 * statistical evaluation (Comment 6). {@code gatewayCert}: bundled test certificate ({@code ecdsa-p256}, default of the
 * testbed; {@code ed25519}, {@code rsa-3072}) or {@code file:<path>} to the real gateway certificate
 * ({@code run-R1C7.sh jmh} uses {@code e2e/probe/gateway.pem} saved by the probe step, if present).
 *
 * <p><b>Not measured here</b> (measured end to end): credential lookup through JPA, {@code PSU_AUDIT} log, audit hash
 * chain written to the database, HTTP/TLS, HTML parsing in the agent. On the auth-server side cb is a configuration
 * array decoded at startup ({@code ChannelBindingResolver}), not recomputed per request.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 8, time = 1)
@Measurement(iterations = 10, time = 1)
@Fork(5)
@State(Scope.Benchmark)
public class NipokAblationBenchmark {

  /** SHA-512 for challenge and nonce: default (JCA: agent, main JMH session) | Conscrypt (auth-server). */
  @Param({"default", "Conscrypt"})
  public String shaProvider;

  /** Gateway certificate used to compute cb: ecdsa-p256 | ed25519 | rsa-3072 | file:&lt;PEM or DER&gt;. */
  @Param({"ecdsa-p256"})
  public String gatewayCert;

  static final String PROVER_ID = "nipok-1";
  static final String VERIFIER_ID = "bank";
  // Constants copied from SimulatorWalletProvider (identical).
  private static final int IV_LEN = 12;
  private static final int TAG_BITS = 128;
  private static final int KEK_LEN = 32;
  private static final byte[] NONCE_KEY_TAG = "NIPoK-nonce-key-v1".getBytes(StandardCharsets.UTF_8);
  private static final byte[] NONCE_TAG = "NIPoK-nonce-v1".getBytes(StandardCharsets.UTF_8);
  private static final Base64.Decoder B64U_DEC = Base64.getUrlDecoder();
  private static final Base64.Encoder B64U_ENC = Base64.getUrlEncoder().withoutPadding();
  private static final BigInteger ELL = BigInteger.ONE.shiftLeft(252)
      .add(new BigInteger("27742317777372353535851937790883648493"));
  private static final SecureRandom RNG = new SecureRandom();

  private Ed25519Group ec;
  private NipokEngine engine;
  private NipokVerifier verifier;
  private SimulatorWalletProvider resident;
  private SimulatorWalletProvider sealed;
  private byte[] x;
  private byte[] bigX;
  private String bigXb64;                  // X as stored in the database (base64url)
  private DiscreteLogCredential cred;
  private NipokContext ctx;
  private NipokProof proof;
  private PreparedPoint prepared;
  private byte[] v;                        // deterministic nonce of ctx (for the separate steps)
  private byte[] e;                        // challenge of the proof
  private byte[] sealedX;                  // SEALED copy: iv||ct||tag
  private ByteBuffer kek;                  // SEALED copy: off-heap KEK
  private X509Certificate cert;
  private String payload;                  // base64url(N||V||s), as the password field sent to /psu/auth
  private ChallengeStoreCopy store;
  private Map<String, PreparedPoint> preparedCache;

  @Setup(Level.Trial)
  public void setup() throws Exception {
    String provider = "default".equals(shaProvider) ? null : shaProvider;
    if ("Conscrypt".equals(shaProvider) && Security.getProvider("Conscrypt") == null) {
      Security.addProvider(org.conscrypt.Conscrypt.newProvider());     // as ConscryptSupport of the auth-server; failure => stop
    }
    ec = new ElisabethEd25519Group(provider);
    engine = new NipokEngine(ec);
    verifier = new NipokVerifier(engine);

    x = ec.randomScalar();
    resident = new SimulatorWalletProvider(x, ec, engine);
    sealed = new SimulatorWalletProvider(x, CustodyMode.SEALED, ec, engine);
    bigX = resident.publicPoint();
    bigXb64 = B64U_ENC.encodeToString(bigX);
    cred = new DiscreteLogCredential(bigX);

    cert = GatewayCerts.load(gatewayCert);
    byte[] cb = agent_step_cb();
    byte[] n = new byte[32];
    RNG.nextBytes(n);
    ctx = new NipokContext(bigX, PROVER_ID, n, cb, VERIFIER_ID);

    proof = sealed.prove(ctx);
    prepared = verifier.prepare(cred);
    v = deriveNonceCopy(x, ctx);
    e = engine.challenge(proof.commitment(), ctx);
    byte[] k = new byte[KEK_LEN];
    RNG.nextBytes(k);
    kek = ByteBuffer.allocateDirect(KEK_LEN);
    kek.put(k).rewind();
    sealedX = sealGcmCopy(x, k);
    Arrays.fill(k, (byte) 0);
    payload = agent_step_payload_encode();
    store = new ChallengeStoreCopy(100_000, 60);
    preparedCache = Collections.synchronizedMap(new LinkedHashMap<>(512, 0.75f, true) {
      @Override protected boolean removeEldestEntry(Map.Entry<String, PreparedPoint> eldest) {
        return size() > 4096;
      }
    });
    preparedCache.put(bigXb64, prepared);
    gate();
  }

  /** Correctness gate (outside the measurement): the copies must match the real code; failure => stop, nothing is measured. */
  void gate() {
    NipokProof r = resident.prove(ctx);
    check(Arrays.equals(r.commitment(), proof.commitment()) && Arrays.equals(r.response(), proof.response()),
        "RESIDENT and SEALED give different proofs (the deterministic nonce must give the same proof)");
    byte[] vv = deriveNonceCopy(x, ctx);
    byte[] bigV = ec.scalarMultBase(vv);
    byte[] ee = engine.challenge(bigV, ctx);
    byte[] ss = ec.scalarSubMul(vv, ee, x);
    check(Arrays.equals(bigV, proof.commitment()) && Arrays.equals(ss, proof.response()),
        "the copy of deriveNonce and the separate steps do not reproduce the proof of the real code");
    check(Arrays.equals(agent_step_unseal(), x), "the copy of unsealGcm does not return x");
    byte[][] nvs = as_step_payload_decode();
    check(Arrays.equals(nvs[0], ctx.serverNonce()) && Arrays.equals(nvs[1], proof.commitment())
        && Arrays.equals(nvs[2], proof.response()), "payload encoding/decoding wrong");
    check(verifier.verify(prepared, proof, ctx).ok() && verifier.verify(cred, proof, ctx).ok() && as_step_equation(),
        "verify rejects a valid proof");
    byte[] forged = proof.response().clone();
    forged[0] ^= 0x01;
    check(!verifier.verify(prepared, new NipokProof(proof.commitment(), forged), ctx).ok(), "verify accepts a forged proof");
    check(NipokEncoding.isCanonicalScalar(proof.response()), "s of a valid proof treated as non-canonical");
    byte[] sPlusL = le32(new BigInteger(1, reverse(proof.response())).add(ELL));
    check(!NipokEncoding.isCanonicalScalar(sPlusL), "s + l not rejected (conformance class L1)");
    check(decodeOrNull(encodePayload(ctx.serverNonce(), proof.commitment(), sPlusL)) == null,
        "decoding accepts s + l");
    check(NipokEncoding.isValidEnrollmentKey(bigX), "valid key X rejected at registration");
    byte[] bad = bigX.clone();
    bad[31] ^= (byte) 0x80;                                 // flips the sign bit of x: may still be valid, only checks that nothing is thrown
    NipokEncoding.isValidEnrollmentKey(bad);
    String id = store.issue().orElseThrow();
    check(store.consume(id) && !store.consume(id), "nonce store is not one-time");
    check(as_auth_total(), "the reduced authenticate() path rejects a valid proof");
    check(cert != null && agent_step_cb().length == 32, "cb must be 32 bytes long");
  }

  // -- Agent side (customer-agent, SEALED mode end to end) -----------------

  /** prove with resident x (as in the main JMH session NipokBenchmark.prove_client, but with cb). */
  @Benchmark @Threads(1)
  public NipokProof agent_prove_resident() { return resident.prove(ctx); }

  /** prove as end to end: decrypt x (AES-256-GCM) -> derive nonce -> V -> e -> s -> erase x. */
  @Benchmark @Threads(1)
  public NipokProof agent_prove_sealed() { return sealed.prove(ctx); }

  /** Step 1: wallet decryption (copy of unsealGcm: kek.get(0, k)). */
  @Benchmark @Threads(1)
  public byte[] agent_step_unseal() {
    byte[] k = new byte[KEK_LEN];
    try {
      kek.get(0, k);
      byte[] iv = Arrays.copyOfRange(sealedX, 0, IV_LEN);
      Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
      c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k, "AES"), new GCMParameterSpec(TAG_BITS, iv));
      return c.doFinal(sealedX, IV_LEN, sealedX.length - IV_LEN);
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException(ex);
    } finally {
      Arrays.fill(k, (byte) 0);
    }
  }

  /** Step 2: deterministic nonce derivation (copy of deriveNonce: two tagged hashToScalar calls). */
  @Benchmark @Threads(1)
  public byte[] agent_step_derive_nonce() { return deriveNonceCopy(x, ctx); }

  /** Step 3: commitment V = vB (fixed base, basepoint table of elisabeth). */
  @Benchmark @Threads(1)
  public byte[] agent_step_commitment() { return ec.scalarMultBase(v); }

  /** Step 4: challenge e = H(B||V||X||id_P||N||cb||id_V) (same function in agent and auth-server). */
  @Benchmark @Threads(1)
  public byte[] agent_step_challenge() { return engine.challenge(proof.commitment(), ctx); }

  /** Step 5: response s = v - e*x mod l. */
  @Benchmark @Threads(1)
  public byte[] agent_step_response() { return ec.scalarSubMul(v, e, x); }

  /** cb = SHA-256(DER of the gateway certificate): copy of ChannelBinding.tlsServerEndPoint (except reading the certificate from the TLS session). */
  @Benchmark @Threads(1)
  public byte[] agent_step_cb() {
    try {
      return MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException(ex);
    }
  }

  /** Packs N||V||s (96 bytes), then base64url, as NipokPsuAuthenticator.loginFormFields. */
  @Benchmark @Threads(1)
  public String agent_step_payload_encode() {
    return encodePayload(ctx.serverNonce(), proof.commitment(), proof.response());
  }

  /** All NIPoK work of the agent in one journey: cb + SEALED prove + packing. */
  @Benchmark @Threads(1)
  public String agent_total() {
    byte[] cb = agent_step_cb();
    NipokProof p = sealed.prove(new NipokContext(bigX, PROVER_ID, ctx.serverNonce(), cb, VERIFIER_ID));
    return encodePayload(ctx.serverNonce(), p.commitment(), p.response());
  }

  // -- Auth-server side -----------------------------------------------------

  /** Payload decoding: base64url -> 96 bytes -> N, V, s + canonical-s check, as at the start of authenticate(). */
  @Benchmark @Threads(1)
  public byte[][] as_step_payload_decode() {
    byte[][] nvs = decodeOrNull(payload);
    if (nvs == null) {
      throw new IllegalStateException("payload rejected");
    }
    return nvs;
  }

  /** Nonce store, one journey: nonce issued (GET /psu/login-page) + nonce consumed (POST /psu/auth), 1 thread. */
  @Benchmark @Threads(1)
  public boolean as_step_nonce_issue_consume() { return store.consume(store.issue().orElseThrow()); }

  /** As above, 8 threads sharing one store (contention on the map, counter and SecureRandom). */
  @Benchmark @Threads(8)
  public boolean as_step_nonce_issue_consume_t8() { return store.consume(store.issue().orElseThrow()); }

  /** Auth-server challenge (SHA-512 of shaProvider). */
  @Benchmark @Threads(1)
  public byte[] as_step_challenge() { return engine.challenge(proof.commitment(), ctx); }

  /** Only the equation V == sB + eX on the precomputed X (comb), e computed beforehand. */
  @Benchmark @Threads(1)
  public boolean as_step_equation() { return prepared.verifySchnorr(proof.commitment(), proof.response(), e); }

  /** Full verify on the precomputed X (default path of the auth-server when X is cached). */
  @Benchmark @Threads(1)
  public boolean as_verify_prepared() { return verifier.verify(prepared, proof, ctx).ok(); }

  /** verify without a precomputed X (Straus; fallback path). */
  @Benchmark @Threads(1)
  public boolean as_verify_cold() { return verifier.verify(cred, proof, ctx).ok(); }

  /** Builds the comb table of X (every miss of the LRU cache of the auth-server: new PSU or evicted entry). */
  @Benchmark @Threads(1)
  public PreparedPoint as_prepare_cache_miss() { return verifier.prepare(cred); }

  /**
   * NIPoK work of the auth-server in one journey, without JPA, log and audit: nonce issued (login page) -> payload decoded
   * and canonical-s check -> nonce consumed -> X decoded from the database string -> comb cache lookup (synchronizedMap,
   * key base64url(X)) -> cb (configuration array) -> verify. The proof is fixed, so the issued nonce is not the N of the proof; the store cost is the same.
   */
  @Benchmark @Threads(1)
  public boolean as_auth_total() {
    String issued = store.issue().orElseThrow();
    byte[][] nvs = decodeOrNull(payload);
    if (nvs == null) {
      return false;
    }
    B64U_ENC.encodeToString(nvs[0]);                       // nonceId as in authenticate() (unused because the proof is fixed)
    if (!store.consume(issued)) {
      return false;
    }
    DiscreteLogCredential c = new DiscreteLogCredential(B64U_DEC.decode(bigXb64));
    byte[] cb = ctx.channelBinding();                      // ChannelBindingResolver.resolve(): configuration array decoded beforehand
    NipokContext context = new NipokContext(c.publicPoint(), PROVER_ID, nvs[0], cb, VERIFIER_ID);
    PreparedPoint pp = preparedCache.computeIfAbsent(B64U_ENC.encodeToString(c.publicPoint()), kk -> verifier.prepare(c));
    return verifier.verify(pp, new NipokProof(nvs[1], nvs[2]), context).ok();
  }

  /** NIPoK key registration at /psu/register: X checked (canonical encoding, no small order, in the subgroup of order l). */
  @Benchmark @Threads(1)
  public boolean reg_validate_key() { return NipokEncoding.isValidEnrollmentKey(B64U_DEC.decode(bigXb64)); }

  // -- Copies and helpers -------------------------------------------------

  /** Decoding stage of NipokAuthenticationProvider: null = rejected (length, base64, non-canonical s). */
  static byte[][] decodeOrNull(String blob) {
    byte[] raw;
    try {
      raw = B64U_DEC.decode(blob);
    } catch (IllegalArgumentException ex) {
      return null;
    }
    if (raw.length != 96) {
      return null;
    }
    byte[] s = Arrays.copyOfRange(raw, 64, 96);
    if (!NipokEncoding.isCanonicalScalar(s)) {
      return null;
    }
    return new byte[][] {Arrays.copyOfRange(raw, 0, 32), Arrays.copyOfRange(raw, 32, 64), s};
  }

  static String encodePayload(byte[] n, byte[] bigV, byte[] s) {
    byte[] blob = new byte[96];
    System.arraycopy(n, 0, blob, 0, 32);
    System.arraycopy(bigV, 0, blob, 32, 32);
    System.arraycopy(s, 0, blob, 64, 32);
    return B64U_ENC.encodeToString(blob);
  }

  private byte[] deriveNonceCopy(byte[] xx, NipokContext c) {
    byte[] prefix = ec.hashToScalar(NONCE_KEY_TAG, xx);
    try {
      return ec.hashToScalar(
          NONCE_TAG, prefix,
          c.publicPoint(),
          c.proverId().getBytes(StandardCharsets.UTF_8),
          c.serverNonce(),
          c.channelBindingOrEmpty(),
          c.verifierId().getBytes(StandardCharsets.UTF_8));
    } finally {
      Arrays.fill(prefix, (byte) 0);
    }
  }

  private static byte[] sealGcmCopy(byte[] plain, byte[] k) throws GeneralSecurityException {
    byte[] iv = new byte[IV_LEN];
    RNG.nextBytes(iv);
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "AES"), new GCMParameterSpec(TAG_BITS, iv));
    byte[] ct = c.doFinal(plain);
    byte[] out = new byte[IV_LEN + ct.length];
    System.arraycopy(iv, 0, out, 0, IV_LEN);
    System.arraycopy(ct, 0, out, IV_LEN, ct.length);
    return out;
  }

  private static byte[] reverse(byte[] a) {
    byte[] r = new byte[a.length];
    for (int i = 0; i < a.length; i++) {
      r[i] = a[a.length - 1 - i];
    }
    return r;
  }

  /** Non-negative integer -> 32 bytes little-endian (the value must be < 2^256). */
  private static byte[] le32(BigInteger n) {
    byte[] be = n.toByteArray();
    byte[] out = new byte[32];
    for (int i = 0; i < be.length && i < 33; i++) {
      int idx = be.length - 1 - i;
      if (i < 32) {
        out[i] = be[idx];
      }
    }
    return out;
  }

  private static void check(boolean ok, String what) {
    if (!ok) {
      throw new IllegalStateException("correctness gate of NipokAblationBenchmark: " + what);
    }
  }

  /** Copy of NipokChallengeStore of the auth-server (logic unchanged; @Component/@Value removed). */
  static final class ChallengeStoreCopy {
    private static final SecureRandom RNG = new SecureRandom();
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private final Map<String, Instant> nonces = new ConcurrentHashMap<>();
    private final AtomicInteger size = new AtomicInteger();
    private final int cap;
    private final Duration ttl;

    ChallengeStoreCopy(int cap, long ttlSeconds) {
      this.cap = cap;
      this.ttl = Duration.ofSeconds(ttlSeconds);
    }

    Optional<String> issue() {
      if (size.get() >= cap) {
        sweep();
        if (size.get() >= cap) {
          return Optional.empty();
        }
      }
      byte[] n = new byte[32];
      RNG.nextBytes(n);
      String id = B64.encodeToString(n);
      if (nonces.putIfAbsent(id, Instant.now().plus(ttl)) == null) {
        size.incrementAndGet();
      }
      return Optional.of(id);
    }

    boolean consume(String nonceB64) {
      Instant exp = nonces.remove(nonceB64);
      if (exp == null) {
        return false;
      }
      size.decrementAndGet();
      return Instant.now().isBefore(exp);
    }

    private void sweep() {
      Instant now = Instant.now();
      nonces.forEach((k, exp) -> {
        if (now.isAfter(exp) && nonces.remove(k, exp)) {
          size.decrementAndGet();
        }
      });
    }
  }
}
