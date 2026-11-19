// C7Probe - operational tests of the security-cost ablation (Reviewer 1, Comment 7): key registration (seven methods),
// NIPoK failure classes and lockout, key lifecycle (revocation, key replacement, recovery), concurrent authentication and
// restart of the auth-server, all through the real gateway of the testbed. Measurement tool run on the host (not service
// code); the services are unchanged.
//
// Run (run-R1C7.sh probe does this): java -cp <crypto-jmh-c7 JMH jar> C7Probe.java   (JDK >= 24, source-file mode)
// The JMH jar contains the psu-auth-spi of the deployed build and elisabeth, so proofs are created by the same code as in
// the customer-agent (SimulatorWalletProvider, deterministic nonce, JCA SHA-512); differences: dedicated test PSUs, their
// own keys, resident x.
//
// Configuration through environment variables (set by run-R1C7.sh):
//   C7_BANK_URL       https://bank.openbanking.dev:30443 (as in run-full-e2e-*.sh)
//   C7_GATEWAY_PEM    gateway certificate (secret istio-system/bank-cluster-certificate); only this certificate is trusted
//   C7_EXPECTED_CB    APP_PSU_NIPOK_EXPECTED_CB of the auth-server; must equal SHA-256(DER of the received gateway certificate)
//   C7_VERIFIER_ID    APP_PSU_NIPOK_VERIFIER_ID (default bank)
//   C7_ONBOARD_TOKEN  X-Onboarding-Token header of POST /psu/register (never printed)
//   C7_ONBOARD_MODE   APP_PSU_ONBOARDING_MODE of the auth-server (enforce | off; Helm: enforce)
//   C7_OUT            output directory (probe.json, probe-raw.csv)
//   C7_PHASES         default register,nipok,lockout,lifecycle,concurrency; the restart phase runs only when listed
//   C7_REG_METHODS    PASSWORD,NIPOK,SCHNORR_INTERACTIVE,ED25519,PRIVATE_KEY_JWT,ML_DSA,MTLS (default: all seven)
//   C7_REG_N=20 C7_REG_WARM=3 C7_FAIL_ROUNDS=5 C7_EXPIRED_ROUNDS=2 C7_NONCE_TTL_S=60 C7_LOCK_MAX=5 C7_LOCK_BASE_S=60
//   C7_KB="kubectl --context bank-cluster-profile" C7_BNS=bank-cluster-nsp C7_AS_LABEL=app.kubernetes.io/name=auth-server
//   C7_LIFE_ROUNDS=10 C7_RACE_K=4 C7_RACE_ROUNDS=20 C7_CONC_USERS=32 C7_CONC_THREADS=16 C7_RESTARTS=3
//   C7_RESTART_TIMEOUT_S=420
//
// Output: one line per attempt in probe-raw.csv; probe.json summarises n, median, p95 and mean (ms), the number of
// unexpected outcomes (an invalid attempt accepted or a valid one rejected) and the status of each phase. Test PSU names:
// c7reg-..., c7probe-... (left in the database).
//
// Phases:
//   - Every phase runs separately (try/catch): a failing phase does not stop the next ones; probe.json records the status
//     of each phase.
//   - lifecycle: onboarding gate (no token, wrong token), malformed public keys (KV02-KV06 of nipok-test-vectors-v1,
//     conformance tests of Comment 8), new registration while the key is active (409); revocation by an operator action
//     (psql in the postgres pod, as in run-all-psu.sh and run-full-e2e-*.sh) => a proof for a challenge obtained BEFORE
//     the revocation and a new login are both rejected; registration of X' while the revoked row still exists (unique
//     constraint customer_id + method); the operator deletes the revoked row => registration of X' => X' can log in, X is
//     rejected.
//   - concurrency: the same proof (one N) sent concurrently from K sessions => accepted exactly once; U different PSUs
//     log in concurrently, the first time (cache of precomputed points of the auth-server misses) and a second time.
//   - restart: N1 consumed, N2 outstanding; the auth-server pod is deleted => wait until the old pod is gone and the
//     login page answers again => proof(N2) and proof(N1) are both rejected, a new login is accepted; the recovery times
//     are recorded.

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.InetAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;

import com.openbanking.psu.auth.spi.crypto.ec.Ed25519Group;
import com.openbanking.psu.auth.spi.crypto.ec.ElisabethEd25519Group;
import com.openbanking.psu.auth.spi.crypto.nipok.NipokEngine;
import com.openbanking.psu.auth.spi.model.NipokContext;
import com.openbanking.psu.auth.spi.model.NipokProof;
import com.openbanking.psu.auth.spi.wallet.SimulatorWalletProvider;

public class C7Probe {

  static final Base64.Encoder B64U = Base64.getUrlEncoder().withoutPadding();
  static final Base64.Decoder B64U_DEC = Base64.getUrlDecoder();
  static final BigInteger ELL = BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
  static final Pattern HIDDEN = Pattern.compile("<input type=\"hidden\" name=\"([^\"]+)\" value=\"([^\"]*)\"");
  static final Pattern SAFE_USER = Pattern.compile("^c7probe-[a-z0-9-]+$");   // test PSU names used in SQL: only a-z0-9-
  static final SecureRandom RNG = new SecureRandom();
  // Malformed NIPoK keys of nipok-test-vectors-v1.json (enrollment_keys, expected = reject).
  static final String[][] BAD_KEYS = {
      {"KV02", "identity point", "0100000000000000000000000000000000000000000000000000000000000000"},
      {"KV03", "point of order 8", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"},
      {"KV04", "mixed-order point", "d086be7013b9505645b99bf257119e4eef77975891e27d04036746ab0dcd4f39"},
      {"KV05", "non-canonical y = 3 + p", "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
      {"KV06", "y with no point on the curve", "0200000000000000000000000000000000000000000000000000000000000000"}};

  static String env(String k, String d) { String v = System.getenv(k); return v == null || v.isBlank() ? d : v.trim(); }
  static int envInt(String k, int d) { return Integer.parseInt(env(k, String.valueOf(d))); }

  final String bank = env("C7_BANK_URL", "https://bank.openbanking.dev:30443");
  final String expectedCb = env("C7_EXPECTED_CB", "");
  final String verifierId = env("C7_VERIFIER_ID", "bank");
  final String onboardToken = env("C7_ONBOARD_TOKEN", "");
  final String onboardMode = env("C7_ONBOARD_MODE", "enforce");
  final Path out = Path.of(env("C7_OUT", "."));
  final int regN = envInt("C7_REG_N", 20), regWarm = envInt("C7_REG_WARM", 3), rounds = envInt("C7_FAIL_ROUNDS", 5);
  final int expiredRounds = envInt("C7_EXPIRED_ROUNDS", 2), ttl = envInt("C7_NONCE_TTL_S", 60);
  final int lockMax = envInt("C7_LOCK_MAX", 5), lockBase = envInt("C7_LOCK_BASE_S", 60);
  final int lifeRounds = envInt("C7_LIFE_ROUNDS", 10), raceK = envInt("C7_RACE_K", 4), raceRounds = envInt("C7_RACE_ROUNDS", 20);
  final int concUsers = envInt("C7_CONC_USERS", 32), concThreads = envInt("C7_CONC_THREADS", 16);
  final int restarts = envInt("C7_RESTARTS", 3), restartTimeout = envInt("C7_RESTART_TIMEOUT_S", 420);
  final List<String> kb = List.of(env("C7_KB", "kubectl --context bank-cluster-profile").split("\\s+"));
  final String bns = env("C7_BNS", "bank-cluster-nsp");
  final String asLabel = env("C7_AS_LABEL", "app.kubernetes.io/name=auth-server");
  final String runId = String.valueOf(Instant.now().getEpochSecond());
  final Ed25519Group ec = new ElisabethEd25519Group(null);            // JCA SHA-512, as in the customer-agent
  final NipokEngine engine = new NipokEngine(ec);
  final SSLContext tls;
  final List<String> raw = new ArrayList<>();
  final Map<String, List<Double>> lat = new LinkedHashMap<>();
  final Map<String, int[]> outcome = new LinkedHashMap<>();           // {as expected, unexpected}
  final Map<String, Object> extra = new LinkedHashMap<>();
  final Map<String, Object> phaseStatus = new LinkedHashMap<>();       // status of each phase
  volatile byte[] cb;                                                 // SHA-256(DER of the received gateway certificate)

  C7Probe() throws Exception {
    String pem = env("C7_GATEWAY_PEM", "");
    if (pem.isEmpty()) {
      throw new IllegalStateException("C7_GATEWAY_PEM is not set");
    }
    KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
    ks.load(null, null);
    Collection<? extends Certificate> certs = CertificateFactory.getInstance("X.509")
        .generateCertificates(new ByteArrayInputStream(Files.readAllBytes(Path.of(pem))));
    int i = 0;
    for (Certificate c : certs) {
      ks.setCertificateEntry("gw" + (i++), c);
    }
    if (i == 0) {
      throw new IllegalStateException("C7_GATEWAY_PEM contains no certificate");
    }
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(ks);
    tls = SSLContext.getInstance("TLS");
    tls.init(null, tmf.getTrustManagers(), null);
  }

  HttpClient client(boolean cookies) {
    HttpClient.Builder b = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).sslContext(tls)
        .followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(10));
    if (cookies) {
      b.cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL));
    }
    return b.build();
  }

  static String form(String... kv) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < kv.length; i += 2) {
      if (kv[i + 1] == null) {
        continue;
      }
      if (sb.length() > 0) {
        sb.append('&');
      }
      sb.append(URLEncoder.encode(kv[i], StandardCharsets.UTF_8)).append('=')
          .append(URLEncoder.encode(kv[i + 1], StandardCharsets.UTF_8));
    }
    return sb.toString();
  }

  // synchronized: the concurrency phase records from several threads.
  synchronized void record(String key, double ms, boolean asExpected, String detail) {
    lat.computeIfAbsent(key, k -> new ArrayList<>()).add(ms);
    int[] o = outcome.computeIfAbsent(key, k -> new int[2]);
    o[asExpected ? 0 : 1]++;
    raw.add(String.join(",", Instant.now().toString(), key, String.format(Locale.ROOT, "%.3f", ms),
        asExpected ? "as_expected" : "UNEXPECTED", detail.replace(',', ';').replace('\n', ' ')));
    if (!asExpected) {
      System.out.println("   ! " + key + ": unexpected (" + detail + ")");
    }
  }

  synchronized void addLat(String key, double ms) {
    lat.computeIfAbsent(key, k -> new ArrayList<>()).add(ms);
  }

  static double msSince(long t0) { return (System.nanoTime() - t0) / 1e6; }

  // -- Key registration: POST /psu/register (seven methods) ---------------------

  record Cred(String method, String publicKey, String password, byte[] x, double keygenMs) { }

  Cred keygen(String method) throws Exception {
    long t0 = System.nanoTime();
    Cred c;
    switch (method) {
      case "PASSWORD" -> {
        byte[] p = new byte[18];
        RNG.nextBytes(p);
        c = new Cred(method, null, B64U.encodeToString(p), null, 0);
      }
      case "NIPOK", "SCHNORR_INTERACTIVE" -> {
        byte[] x = ec.randomScalar();
        c = new Cred(method, B64U.encodeToString(ec.scalarMultBase(x)), null, x, 0);
      }
      case "ED25519", "PRIVATE_KEY_JWT", "MTLS" -> {               // raw 32-byte Ed25519 public key (b64url)
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] spki = kp.getPublic().getEncoded();
        c = new Cred(method, B64U.encodeToString(Arrays.copyOfRange(spki, spki.length - 32, spki.length)), null, null, 0);
      }
      case "ML_DSA" -> {                                            // X.509 SubjectPublicKeyInfo of ML-DSA-65
        KeyPair kp = KeyPairGenerator.getInstance("ML-DSA-65").generateKeyPair();
        c = new Cred(method, B64U.encodeToString(kp.getPublic().getEncoded()), null, null, 0);
      }
      default -> throw new IllegalArgumentException(method);
    }
    double ms = msSince(t0);
    return new Cred(c.method(), c.publicKey(), c.password(), c.x(), ms);
  }

  /** POST /psu/register; token = null => no X-Onboarding-Token header. */
  HttpResponse<String> registerRaw(HttpClient http, String username, String method, String publicKey, String password,
                                   String token) throws Exception {
    HttpRequest.Builder rb = HttpRequest.newBuilder(URI.create(bank + "/psu/register"))
        .timeout(Duration.ofSeconds(30)).header("Content-Type", "application/x-www-form-urlencoded")
        .POST(HttpRequest.BodyPublishers.ofString(form("username", username, "method", method,
            "publicKey", publicKey, "password", password)));
    if (token != null && !token.isEmpty()) {
      rb.header("X-Onboarding-Token", token);
    }
    return http.send(rb.build(), HttpResponse.BodyHandlers.ofString());
  }

  HttpResponse<String> register(HttpClient http, String username, Cred c) throws Exception {
    return registerRaw(http, username, c.method(), c.publicKey(), c.password(), onboardToken);
  }

  void phaseRegister() throws Exception {
    System.out.println("== key registration: " + regWarm + " warm-up + " + regN + " measured requests per method");
    HttpClient http = client(false);                                 // one client, connection kept alive
    String[] methods = env("C7_REG_METHODS", "PASSWORD,NIPOK,SCHNORR_INTERACTIVE,ED25519,PRIVATE_KEY_JWT,ML_DSA,MTLS").split(",");
    for (String m : methods) {
      for (int i = 0; i < regWarm + regN; i++) {
        Cred c = keygen(m);
        String user = "c7reg-" + m.toLowerCase(Locale.ROOT).replace('_', '-') + "-" + runId + "-" + i;
        long t0 = System.nanoTime();
        HttpResponse<String> r = register(http, user, c);
        double ms = msSince(t0);
        if (i < regWarm) {
          if (r.statusCode() != 201) {
            System.out.println("   ! warm-up " + m + ": HTTP " + r.statusCode() + " " + abbreviate(r.body()));
          }
          continue;
        }
        record("register." + m, ms, r.statusCode() == 201, "HTTP " + r.statusCode());
        addLat("keygen." + m, c.keygenMs());
      }
    }
  }

  // -- NIPoK login: GET /psu/login-page -> POST /psu/auth -----------------

  record Page(HttpClient http, String csrf, byte[] nonce, double getMs) { }

  Page loginPage(HttpClient http) throws Exception {
    long t0 = System.nanoTime();
    HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(bank + "/psu/login-page"))
        .timeout(Duration.ofSeconds(30)).GET().build(), HttpResponse.BodyHandlers.ofString());
    double ms = msSince(t0);
    if (r.statusCode() != 200) {
      throw new IllegalStateException("GET /psu/login-page: HTTP " + r.statusCode());
    }
    String csrf = null, nonce = null;
    Matcher mt = HIDDEN.matcher(r.body());
    while (mt.find()) {
      if ("_csrf".equals(mt.group(1))) {
        csrf = mt.group(2);
      } else if ("nipokNonce".equals(mt.group(1))) {
        nonce = mt.group(2);
      }
    }
    if (csrf == null || nonce == null || nonce.isEmpty()) {
      throw new IllegalStateException("login page without _csrf or nipokNonce (auth-server not in active-method=nipok?)");
    }
    if (cb == null) {                                                // cb as in ChannelBinding.tlsServerEndPoint of the agent
      SSLSession s = r.sslSession().orElseThrow(() -> new IllegalStateException("no TLS session"));
      byte[] got = MessageDigest.getInstance("SHA-256").digest(s.getPeerCertificates()[0].getEncoded());
      String g = B64U.encodeToString(got);
      synchronized (this) {
        extra.put("cb_from_tls", g);
        extra.put("cb_matches_expected", g.equals(expectedCb));
      }
      if (!g.equals(expectedCb)) {
        throw new IllegalStateException("cb of the gateway certificate (" + g + ") differs from APP_PSU_NIPOK_EXPECTED_CB - stopping");
      }
      cb = got;
    }
    return new Page(http, csrf, B64U_DEC.decode(nonce), ms);
  }

  /** POST /psu/auth; returns {ms, success?} (success = 302 not to the error page). Closes the client of the attempt. */
  double[] submit(Page p, String username, String passwordField) throws Exception {
    long t0 = System.nanoTime();
    HttpResponse<String> r;
    try {
      r = p.http().send(HttpRequest.newBuilder(URI.create(bank + "/psu/auth"))
          .timeout(Duration.ofSeconds(30)).header("Content-Type", "application/x-www-form-urlencoded")
          .POST(HttpRequest.BodyPublishers.ofString(form("username", username, "password", passwordField, "_csrf", p.csrf())))
          .build(), HttpResponse.BodyHandlers.ofString());
    } finally {
      p.http().close();
    }
    double ms = msSince(t0);
    String loc = r.headers().firstValue("Location").orElse("");
    boolean success = r.statusCode() == 302 && !loc.contains("error") && !loc.contains("/psu/login-page");
    return new double[] {ms, success ? 1 : 0};
  }

  record User(String name, byte[] x, byte[] bigX, SimulatorWalletProvider wallet) { }

  User userOf(String name, Cred c) {
    return new User(name, c.x(), B64U_DEC.decode(c.publicKey()), new SimulatorWalletProvider(c.x(), ec, engine));
  }

  User newNipokUser(HttpClient regHttp, String tag) throws Exception {
    Cred c = keygen("NIPOK");
    String name = "c7probe-" + tag + "-" + runId;
    HttpResponse<String> r = register(regHttp, name, c);
    if (r.statusCode() != 201) {
      throw new IllegalStateException("registration " + name + ": HTTP " + r.statusCode() + " " + abbreviate(r.body()));
    }
    return userOf(name, c);
  }

  static String payload(byte[] n, byte[] v, byte[] s) {
    byte[] blob = new byte[n.length + v.length + s.length];
    System.arraycopy(n, 0, blob, 0, n.length);
    System.arraycopy(v, 0, blob, n.length, v.length);
    System.arraycopy(s, 0, blob, n.length + v.length, s.length);
    return B64U.encodeToString(blob);
  }

  NipokProof prove(User u, String proverId, byte[] n, byte[] channel, String verifier) {
    return u.wallet().prove(new NipokContext(u.bigX(), proverId, n, channel, verifier));
  }

  String validPayload(User u, byte[] n) {
    NipokProof pr = prove(u, u.name(), n, cb, verifierId);
    return payload(n, pr.commitment(), pr.response());
  }

  /** One login with a valid proof of u; records the outcome against the expectation. Returns true if accepted. */
  boolean loginAs(User u, String key, boolean expectOk) throws Exception {
    Page p = loginPage(client(true));
    double[] r = submit(p, u.name(), validPayload(u, p.nonce()));
    boolean ok = r[1] == 1;
    record(key, r[0], ok == expectOk, ok ? "accepted" : "rejected");
    addLat("login_page.GET", p.getMs());
    return ok;
  }

  /** One valid login (also resets the lockout counter of the user). Returns the N used. */
  byte[] validLogin(User u, String key) throws Exception {
    Page p = loginPage(client(true));
    double[] r = submit(p, u.name(), validPayload(u, p.nonce()));
    record(key, r[0], r[1] == 1, r[1] == 1 ? "ok" : "rejected");
    addLat("login_page.GET", p.getMs());
    return p.nonce();
  }

  void ensureCb() throws Exception {
    if (cb == null) {
      Page p = loginPage(client(true));                               // sequential: sets cb before the parallel runs
      p.http().close();
    }
  }

  static byte[] le32(BigInteger n) {
    byte[] be = n.toByteArray();
    byte[] le = new byte[32];
    for (int i = 0; i < 32 && i < be.length; i++) {
      le[i] = be[be.length - 1 - i];
    }
    return le;
  }

  static byte[] rev(byte[] a) {
    byte[] r = new byte[a.length];
    for (int i = 0; i < a.length; i++) {
      r[i] = a[a.length - 1 - i];
    }
    return r;
  }

  /** One invalid attempt of class {@code cls}; returns true if rejected (as expected). */
  boolean failAttempt(String cls, User u, User other, byte[] usedNonce) throws Exception {
    Page p = loginPage(client(true));
    byte[] n = p.nonce();
    String user = u.name();
    String field;
    switch (cls) {
      case "forged_s" -> {                                           // s with one bit flipped, still < l => equation fails
        NipokProof pr = prove(u, user, n, cb, verifierId);
        byte[] s = pr.response().clone();
        s[0] ^= 0x01;
        field = payload(n, pr.commitment(), s);
      }
      case "noncanonical_s" -> {                                     // s + l (same proof, non-canonical encoding; conformance class L1)
        NipokProof pr = prove(u, user, n, cb, verifierId);
        BigInteger s2 = new BigInteger(1, rev(pr.response())).add(ELL);
        if (s2.bitLength() > 256) {
          s2 = new BigInteger(1, rev(pr.response()));                // rare: s + l >= 2^256 => s is used (counted as unexpected)
        }
        field = payload(n, pr.commitment(), le32(s2));
      }
      case "bad_length" -> {                                         // 95 bytes instead of 96
        NipokProof pr = prove(u, user, n, cb, verifierId);
        field = B64U.encodeToString(Arrays.copyOf(Base64.getUrlDecoder().decode(payload(n, pr.commitment(), pr.response())), 95));
      }
      case "bad_encoding" -> field = "!!" + "A".repeat(126);        // not base64url
      case "replayed_nonce" -> {                                     // N consumed by the previous valid login, valid proof for that N
        NipokProof pr = prove(u, user, usedNonce, cb, verifierId);
        field = payload(usedNonce, pr.commitment(), pr.response());
      }
      case "unknown_nonce" -> {                                      // N never issued
        byte[] rn = new byte[32];
        RNG.nextBytes(rn);
        NipokProof pr = prove(u, user, rn, cb, verifierId);
        field = payload(rn, pr.commitment(), pr.response());
      }
      case "wrong_cb" -> {                                           // proof bound to another channel (cb differs)
        byte[] badCb = MessageDigest.getInstance("SHA-256").digest("c7-other-channel".getBytes(StandardCharsets.UTF_8));
        NipokProof pr = prove(u, user, n, badCb, verifierId);
        field = payload(n, pr.commitment(), pr.response());
      }
      case "wrong_verifier" -> {                                     // proof for another verifier (id_V differs: cross-relay)
        NipokProof pr = prove(u, user, n, cb, verifierId + "-other");
        field = payload(n, pr.commitment(), pr.response());
      }
      case "other_user_proof" -> {                                   // valid proof of another user, sent as u
        NipokProof pr = prove(other, other.name(), n, cb, verifierId);
        field = payload(n, pr.commitment(), pr.response());
      }
      default -> throw new IllegalArgumentException(cls);
    }
    double[] r = submit(p, user, field);
    record("fail." + cls, r[0], r[1] == 0, r[1] == 0 ? "rejected" : "ACCEPTED");
    addLat("login_page.GET", p.getMs());
    return r[1] == 0;
  }

  void phaseNipok() throws Exception {
    String[] classes = {"forged_s", "noncanonical_s", "bad_length", "bad_encoding", "replayed_nonce", "unknown_nonce",
                        "wrong_cb", "wrong_verifier", "other_user_proof"};
    int perRound = lockMax - 1;                                       // < lockout threshold; the valid login resets the counter
    System.out.println("== NIPoK login: " + rounds + " rounds x (1 valid + " + perRound + " invalid) per failure class; "
        + "expired nonce: " + expiredRounds + " rounds (wait " + (ttl + 2) + " s)");
    HttpClient regHttp = client(false);
    User other = newNipokUser(regHttp, "other");
    for (int i = 0; i < 3; i++) {                                     // warm-up (not recorded)
      Page p = loginPage(client(true));
      submit(p, other.name(), validPayload(other, p.nonce()));
    }
    for (String cls : classes) {
      User u = newNipokUser(regHttp, cls.replace('_', '-'));
      for (int r = 0; r < rounds; r++) {
        byte[] used = validLogin(u, "login.valid");
        for (int k = 0; k < perRound; k++) {
          failAttempt(cls, u, other, used);
        }
      }
      validLogin(u, "login.valid");
    }
    // Expired nonce: get the login page, wait longer than the TTL of the nonce store, then send a valid proof.
    User u = newNipokUser(regHttp, "expired-nonce");
    for (int r = 0; r < expiredRounds; r++) {
      validLogin(u, "login.valid");
      List<Page> pages = new ArrayList<>();
      for (int k = 0; k < perRound; k++) {
        pages.add(loginPage(client(true)));
      }
      Thread.sleep((ttl + 2) * 1000L);
      for (Page p : pages) {
        double[] res = submit(p, u.name(), validPayload(u, p.nonce()));
        record("fail.expired_nonce", res[0], res[1] == 0, res[1] == 0 ? "rejected" : "ACCEPTED");
      }
    }
    validLogin(u, "login.valid");
  }

  // -- Lockout: LockoutAuthenticationProvider (all form-login mechanisms) -------

  void phaseLockout() throws Exception {
    System.out.println("== lockout: " + lockMax + " consecutive invalid proofs => locked for " + lockBase + " s; retry every 5 s");
    User u = newNipokUser(client(false), "lockout");
    validLogin(u, "lockout.valid_before");
    long lockAt = 0;
    for (int k = 0; k < lockMax; k++) {
      failAttempt("forged_s", u, u, null);
      lockAt = System.nanoTime();
    }
    // Right after the lock: a VALID proof must also be rejected (counter not increased: LockedException before the proof check).
    Page p = loginPage(client(true));
    double[] r = submit(p, u.name(), validPayload(u, p.nonce()));
    record("lockout.valid_while_locked", r[0], r[1] == 0, r[1] == 0 ? "rejected (locked)" : "ACCEPTED although locked");
    double unlockS = -1;
    int polls = 0;
    long deadline = lockAt + (lockBase + 30L) * 1_000_000_000L;
    while (System.nanoTime() < deadline) {
      Thread.sleep(5000);
      polls++;
      p = loginPage(client(true));
      r = submit(p, u.name(), validPayload(u, p.nonce()));
      if (r[1] == 1) {
        unlockS = (System.nanoTime() - lockAt) / 1e9;
        record("lockout.valid_after_unlock", r[0], true, "unlocked after " + String.format(Locale.ROOT, "%.1f", unlockS) + " s");
        break;
      }
      record("lockout.valid_while_locked", r[0], true, "rejected (locked)");
    }
    if (unlockS < 0) {
      record("lockout.valid_after_unlock", 0, false, "still locked after " + (lockBase + 30) + " s");
    }
    synchronized (this) {
      extra.put("lockout_unlock_after_s", unlockS);
      extra.put("lockout_expected_s", lockBase);
      extra.put("lockout_polls", polls);
    }
    // After unlocking and a valid login: counter back to 0 => one invalid attempt does not lock again.
    failAttempt("forged_s", u, u, null);
    validLogin(u, "lockout.valid_after_reset");
  }

  // -- Operator actions: kubectl (psql in the postgres pod; auth-server pod) --

  record Cmd(int code, String out, String err, double ms) { }

  /**
   * Runs kubectl with the prefix C7_KB (no shell => no quoting issues); more than 120 s => exception. stdout and
   * stderr are kept apart: kubectl exec prints "Defaulted container ..." to stderr when the pod has an istio-proxy sidecar.
   */
  Cmd kubectl(String... args) throws Exception {
    List<String> cmd = new ArrayList<>(kb);
    cmd.addAll(List.of(args));
    long t0 = System.nanoTime();
    Path o = Files.createTempFile("c7probe-kubectl", ".out"), e = Files.createTempFile("c7probe-kubectl", ".err");
    try {
      Process p = new ProcessBuilder(cmd).redirectOutput(o.toFile()).redirectError(e.toFile()).start();
      if (!p.waitFor(120, TimeUnit.SECONDS)) {
        p.destroyForcibly();
        throw new IllegalStateException("kubectl took more than 120 s: " + String.join(" ", args));
      }
      return new Cmd(p.exitValue(), Files.readString(o, StandardCharsets.UTF_8).strip(),
          Files.readString(e, StandardCharsets.UTF_8).strip(), msSince(t0));
    } finally {
      Files.deleteIfExists(o);
      Files.deleteIfExists(e);
    }
  }

  /** SQL through psql in the postgres pod (as in run-all-psu.sh: psql -tAU user customer_identity). Only for test PSUs c7probe-.... */
  Cmd sql(String user, String statement) throws Exception {
    if (!SAFE_USER.matcher(user).matches()) {
      throw new IllegalArgumentException("test PSU name not allowed in SQL: " + user);
    }
    return kubectl("-n", bns, "exec", "deploy/postgres", "--", "psql", "-qtAU", "user", "customer_identity", "-c",
        statement.replace("{user}", user));
  }

  static final String SQL_REVOKE = "update customer_credential set enabled=false where method='NIPOK' and enabled"
      + " and customer_id=(select customer_id from customer where username='{user}') returning enabled";
  static final String SQL_DELETE_REVOKED = "delete from customer_credential where method='NIPOK' and not enabled"
      + " and customer_id=(select customer_id from customer where username='{user}') returning 1";

  // -- Key lifecycle: registration gate, revocation, key replacement, recovery ------

  void phaseLifecycle() throws Exception {
    System.out.println("== key lifecycle: onboarding gate (" + onboardMode + "), " + BAD_KEYS.length + " malformed keys, "
        + lifeRounds + " rounds (409, revocation, new registration, new key)");
    HttpClient http = client(false);
    ensureCb();
    // (1) Onboarding gate: no token and wrong token. Helm sets mode=enforce => 403; mode=off => accepted (201).
    boolean enforce = !"off".equalsIgnoreCase(onboardMode);
    for (String variant : new String[] {"none", "wrong"}) {
      Cred c = keygen("NIPOK");
      String name = "c7probe-gate" + variant + "-" + runId;
      long t0 = System.nanoTime();
      HttpResponse<String> r = registerRaw(http, name, "NIPOK", c.publicKey(), null,
          variant.equals("none") ? null : "c7-wrong-token-" + runId);
      boolean exp = enforce ? r.statusCode() == 403 : r.statusCode() == 201;
      record("life.gate_token_" + variant, msSince(t0), exp, "HTTP " + r.statusCode() + " (mode " + onboardMode + ")");
    }
    // (2) Malformed public keys (KV02-KV06 of the conformance vectors): 400 expected.
    for (String[] k : BAD_KEYS) {
      String name = "c7probe-badkey-" + k[0].toLowerCase(Locale.ROOT) + "-" + runId;
      String pk = B64U.encodeToString(HexFormat.of().parseHex(k[2]));
      long t0 = System.nanoTime();
      HttpResponse<String> r = registerRaw(http, name, "NIPOK", pk, null, onboardToken);
      record("life.bad_key", msSince(t0), r.statusCode() == 400,
          k[0] + " " + k[1] + ": HTTP " + r.statusCode() + " " + abbreviate(r.body()));
    }
    // (3) Rounds: register X -> 409 while active -> revoke (operator) -> X rejected, also with a challenge obtained earlier
    //     -> register X' while the revoked row exists -> operator deletes the revoked row -> register X' -> X' accepted, X rejected.
    Map<Integer, Integer> overRevoked = new TreeMap<>();
    for (int r = 0; r < lifeRounds; r++) {
      String name = "c7probe-life" + r + "-" + runId;
      Cred cx = keygen("NIPOK");
      long t0 = System.nanoTime();
      HttpResponse<String> rr = register(http, name, cx);
      record("life.register_X", msSince(t0), rr.statusCode() == 201, "HTTP " + rr.statusCode());
      if (rr.statusCode() != 201) {
        throw new IllegalStateException("registration " + name + ": HTTP " + rr.statusCode() + " " + abbreviate(rr.body()));
      }
      User ux = userOf(name, cx);
      loginAs(ux, "life.login_X_before_revoke", true);
      Cred cy = keygen("NIPOK");
      t0 = System.nanoTime();
      rr = register(http, name, cy);
      record("life.register_while_active", msSince(t0), rr.statusCode() == 409, "HTTP " + rr.statusCode());
      // Challenge obtained BEFORE the revocation; proof computed in advance, not yet sent.
      Page pa = loginPage(client(true));
      String fa = validPayload(ux, pa.nonce());
      Cmd rv = sql(name, SQL_REVOKE);
      boolean rvOk = rv.code() == 0 && rv.out().equals("f");
      record("life.op_revoke_sql", rv.ms(), rvOk, "exit " + rv.code() + " out=" + abbreviate(rv.out())
          + (rvOk ? "" : " err=" + abbreviate(rv.err())));
      if (!rvOk) {
        throw new IllegalStateException("SQL revocation did not affect exactly one row (" + name + "): exit " + rv.code() + " "
            + abbreviate(rv.out()) + " " + abbreviate(rv.err()));
      }
      double[] s1 = submit(pa, name, fa);
      record("life.earlier_challenge_after_revoke", s1[0], s1[1] == 0, s1[1] == 0 ? "rejected" : "ACCEPTED");
      loginAs(ux, "life.login_X_after_revoke", false);
      // Registration of X' while the revoked row exists: unique constraint (customer_id, method) => no 201.
      t0 = System.nanoTime();
      rr = register(http, name, cy);
      overRevoked.merge(rr.statusCode(), 1, Integer::sum);
      record("life.register_over_revoked_row", msSince(t0), rr.statusCode() != 201,
          "HTTP " + rr.statusCode() + " " + abbreviate(rr.body()));
      if (rr.statusCode() == 201) {
        throw new IllegalStateException("registration of X' accepted although the revoked row exists (" + name + ") - phase stopped");
      }
      // The operator deletes the revoked row, then registers X' (as in run-full-e2e-*.sh: delete, then /psu/register).
      Cmd dl = sql(name, SQL_DELETE_REVOKED);
      boolean dlOk = dl.code() == 0 && dl.out().equals("1");
      record("life.op_delete_revoked_sql", dl.ms(), dlOk, "exit " + dl.code() + " out=" + abbreviate(dl.out())
          + (dlOk ? "" : " err=" + abbreviate(dl.err())));
      if (!dlOk) {
        throw new IllegalStateException("deletion of the revoked row did not affect exactly one row (" + name + "): exit " + dl.code() + " "
            + abbreviate(dl.out()) + " " + abbreviate(dl.err()));
      }
      t0 = System.nanoTime();
      rr = register(http, name, cy);
      record("life.register_X_new", msSince(t0), rr.statusCode() == 201, "HTTP " + rr.statusCode());
      if (rr.statusCode() != 201) {
        throw new IllegalStateException("registration of X' after deleting the revoked row: HTTP " + rr.statusCode());
      }
      User uy = userOf(name, cy);
      loginAs(uy, "life.login_X_new", true);
      loginAs(ux, "life.login_X_old_after_rotation", false);
      loginAs(uy, "life.login_X_new", true);                         // also resets the lockout counter of this PSU
    }
    synchronized (this) {
      extra.put("life_register_over_revoked_row_http", overRevoked);
      extra.put("life_onboard_mode", onboardMode);
    }
  }

  // -- Concurrency: one N sent in parallel; many different PSUs -------------

  void phaseConcurrency() throws Exception {
    int k = Math.min(raceK, Math.max(2, lockMax));                    // K - 1 invalid attempts < lockout threshold
    System.out.println("== concurrency: the same proof (one N) from " + k + " sessions x " + raceRounds + " rounds; " + concUsers
        + " different PSUs, " + concThreads + " threads, 2 passes");
    ensureCb();
    ExecutorService pool = Executors.newFixedThreadPool(Math.max(k, concThreads));
    try {
      // (a) One N, K concurrent submissions: compare-and-delete in the nonce store => accepted exactly once.
      User u = newNipokUser(client(false), "race");
      validLogin(u, "race.valid_reset");
      int[] winners = new int[k + 1];
      for (int r = 0; r < raceRounds; r++) {
        List<Page> pages = new ArrayList<>();
        for (int i = 0; i < k; i++) {
          pages.add(loginPage(client(true)));                         // every session has its own cookie and CSRF token
        }
        String field = validPayload(u, pages.get(0).nonce());        // proof bound to the N of the first page
        CountDownLatch go = new CountDownLatch(1);
        List<Future<double[]>> fs = new ArrayList<>();
        for (Page p : pages) {
          fs.add(pool.submit(() -> {
            go.await();
            return submit(p, u.name(), field);
          }));
        }
        go.countDown();
        int wins = 0;
        double maxMs = 0;
        for (Future<double[]> f : fs) {
          double[] res = f.get(120, TimeUnit.SECONDS);
          wins += (int) res[1];
          maxMs = Math.max(maxMs, res[0]);
          addLat("race.submit", res[0]);
        }
        winners[wins]++;
        record("race.one_nonce_k_submissions", maxMs, wins == 1, "accepted " + wins + "/" + k);
        validLogin(u, "race.valid_reset");                            // resets the lockout counter (K - 1 invalid attempts)
      }
      Map<String, Integer> hist = new LinkedHashMap<>();
      for (int i = 0; i <= k; i++) {
        hist.put(String.valueOf(i), winners[i]);
      }
      // (b) Many different PSUs log in concurrently: pass 1 = first login of every PSU (precomputed-point cache misses),
      //     pass 2 = second login (cache hits).
      HttpClient reg = client(false);
      List<User> users = new ArrayList<>();
      for (int i = 0; i < concUsers; i++) {
        users.add(newNipokUser(reg, "conc" + i));
      }
      for (int pass = 1; pass <= 2; pass++) {
        String key = pass == 1 ? "conc.login_first" : "conc.login_second";
        CountDownLatch go = new CountDownLatch(1);
        List<Future<Boolean>> fs = new ArrayList<>();
        for (User x : users) {
          Callable<Boolean> task = () -> {
            go.await();
            return loginAs(x, key, true);
          };
          fs.add(pool.submit(task));
        }
        long t0 = System.nanoTime();
        go.countDown();
        int okN = 0;
        for (Future<Boolean> f : fs) {
          okN += f.get(300, TimeUnit.SECONDS) ? 1 : 0;
        }
        double wall = msSince(t0);
        synchronized (this) {
          extra.put("conc_pass" + pass + "_ok", okN);
          extra.put("conc_pass" + pass + "_wall_ms", wall);
        }
      }
      synchronized (this) {
        extra.put("race_k", k);
        extra.put("race_winners_histogram", hist);
        extra.put("conc_users", concUsers);
        extra.put("conc_threads", concThreads);
      }
    } finally {
      pool.shutdownNow();
    }
  }

  // -- Restart of the auth-server: the in-memory nonce store is lost => outstanding and consumed N are both rejected --

  int pageStatus() {
    HttpClient h = client(true);
    try {
      return h.send(HttpRequest.newBuilder(URI.create(bank + "/psu/login-page")).timeout(Duration.ofSeconds(5)).GET().build(),
          HttpResponse.BodyHandlers.discarding()).statusCode();
    } catch (Exception e) {
      return -1;
    } finally {
      h.close();
    }
  }

  /** Is a new auth-server pod (name not in {@code old}) Ready? Read through jsonpath, read-only. */
  String newReadyPod(List<String> old) throws Exception {
    Cmd c = kubectl("-n", bns, "get", "pods", "-l", asLabel, "-o",
        "jsonpath={range .items[*]}{.metadata.name}{\" \"}{.status.conditions[?(@.type==\"Ready\")].status}{\"\\n\"}{end}");
    if (c.code() != 0) {
      return null;
    }
    for (String l : c.out().split("\\R")) {
      String[] f = l.strip().split("\\s+");
      if (f.length == 2 && !old.contains("pod/" + f[0]) && "True".equals(f[1])) {
        return "pod/" + f[0];
      }
    }
    return null;
  }

  List<String> asPods() throws Exception {
    Cmd c = kubectl("-n", bns, "get", "pods", "-l", asLabel, "-o", "name");
    if (c.code() != 0) {
      throw new IllegalStateException("kubectl get pods -l " + asLabel + ": exit " + c.code() + " " + abbreviate(c.err()));
    }
    List<String> r = new ArrayList<>();
    for (String l : c.out().split("\\R")) {
      if (l.strip().startsWith("pod/")) {
        r.add(l.strip());
      }
    }
    return r;
  }

  void phaseRestart() throws Exception {
    System.out.println("== auth-server restart: " + restarts + " times (delete pod -l " + asLabel + "; wait at most "
        + restartTimeout + " s)");
    ensureCb();
    User u = newNipokUser(client(false), "restart");
    List<Map<String, Object>> runs = new ArrayList<>();
    for (int i = 0; i < restarts; i++) {
      validLogin(u, "restart.valid_before");                          // also resets the lockout counter
      // N1: consumed just before the pod is deleted.
      Page p1 = loginPage(client(true));
      String f1 = validPayload(u, p1.nonce());
      double[] r1 = submit(p1, u.name(), f1);
      record("restart.consume_N1_before", r1[0], r1[1] == 1, r1[1] == 1 ? "ok" : "rejected");
      // N2: outstanding (proof computed in advance, not yet sent).
      Page p2 = loginPage(client(true));
      String f2 = validPayload(u, p2.nonce());
      p2.http().close();
      List<String> old = asPods();
      if (old.isEmpty()) {
        throw new IllegalStateException("no auth-server pod found (-l " + asLabel + ")");
      }
      List<String> del = new ArrayList<>(List.of("-n", bns, "delete"));
      del.addAll(old);
      del.addAll(List.of("--grace-period=0", "--force", "--wait=false"));
      long t0 = System.nanoTime();
      Cmd d = kubectl(del.toArray(new String[0]));
      if (d.code() != 0) {
        throw new IllegalStateException("deleting the auth-server pod: exit " + d.code() + " " + abbreviate(d.err()));
      }
      long deadline = t0 + restartTimeout * 1_000_000_000L;
      double goneS = -1, readyS = -1, pageS = -1, loginS = -1;
      String fresh = null;
      while (System.nanoTime() < deadline) {                           // old pod no longer in the API
        boolean gone = true;
        for (String o : old) {
          if (kubectl("-n", bns, "get", o, "-o", "name").code() == 0) {
            gone = false;
            break;
          }
        }
        if (gone) {
          goneS = msSince(t0) / 1000;
          break;
        }
        Thread.sleep(1000);
      }
      // New pod Ready (readiness probe: initialDelaySeconds 10, periodSeconds 15) => the old container stopped long ago,
      // Envoy routes only to the new pod; then wait until the login page returns 200.
      while (goneS >= 0 && System.nanoTime() < deadline) {
        fresh = newReadyPod(old);
        if (fresh != null) {
          readyS = msSince(t0) / 1000;
          break;
        }
        Thread.sleep(1000);
      }
      while (readyS >= 0 && System.nanoTime() < deadline) {
        if (pageStatus() == 200) {
          pageS = msSince(t0) / 1000;
          break;
        }
        Thread.sleep(1000);
      }
      if (pageS < 0) {
        record("restart.recovered", msSince(t0), false, "more than " + restartTimeout + " s (old pod gone: " + (goneS >= 0)
            + ", new pod Ready: " + (readyS >= 0) + ")");
        throw new IllegalStateException("auth-server not answering after " + restartTimeout + " s");
      }
      List<String> now = asPods();
      // New session (new pod): the proofs of N2 (outstanding at the deletion) and of N1 (consumed) must both be rejected.
      Page q2 = loginPage(client(true));
      double[] a2 = submit(q2, u.name(), f2);
      record("restart.outstanding_N2_after", a2[0], a2[1] == 0, a2[1] == 0 ? "rejected" : "ACCEPTED");
      Page q1 = loginPage(client(true));
      double[] a1 = submit(q1, u.name(), f1);
      record("restart.consumed_N1_replay_after", a1[0], a1[1] == 0, a1[1] == 0 ? "rejected" : "ACCEPTED");
      // First valid login after the restart (at most 10 attempts, 2 s apart; only one outcome recorded).
      int tries = 0;
      double[] lr = {0, 0};
      while (tries < 10 && System.nanoTime() < deadline) {
        tries++;
        Page q = loginPage(client(true));
        lr = submit(q, u.name(), validPayload(u, q.nonce()));
        if (lr[1] == 1) {
          break;
        }
        Thread.sleep(2000);
      }
      boolean ok = lr[1] == 1;
      loginS = ok ? msSince(t0) / 1000 : -1;
      record("restart.first_valid_login", lr[0], ok, (ok ? "accepted" : "rejected") + " at attempt " + tries);
      record("restart.recovered", msSince(t0), ok, ok ? "login possible after " + String.format(Locale.ROOT, "%.1f", loginS) + " s"
          : "login not yet possible");
      Map<String, Object> m = new LinkedHashMap<>();
      m.put("pods_before", String.join(" ", old));
      m.put("pods_after", String.join(" ", now));
      m.put("new_pod", fresh);
      m.put("old_pod_gone_s", goneS);
      m.put("new_pod_ready_s", readyS);
      m.put("login_page_up_s", pageS);
      m.put("first_valid_login_s", loginS);
      runs.add(m);
      System.out.printf(Locale.ROOT, "   restart %d: old pod gone %.1f s, new pod Ready %.1f s, login page %.1f s,"
          + " valid login %.1f s%n", i + 1, goneS, readyS, pageS, loginS);
    }
    synchronized (this) {
      extra.put("restart_runs", runs);
    }
  }

  // -- Summary --------------------------------------------------------------

  static String abbreviate(String s) { return s == null ? "" : (s.length() > 160 ? s.substring(0, 160) + "..." : s); }

  static Map<String, Object> stats(List<Double> xs) {
    List<Double> v = new ArrayList<>(xs);
    v.sort(null);
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("n", v.size());
    if (!v.isEmpty()) {
      m.put("median_ms", v.get(v.size() / 2));
      m.put("p95_ms", v.get(Math.min(v.size() - 1, (int) Math.ceil(0.95 * v.size()) - 1)));
      m.put("mean_ms", v.stream().mapToDouble(Double::doubleValue).average().orElse(0));
      m.put("max_ms", v.get(v.size() - 1));
    }
    return m;
  }

  static String json(Object o) {
    if (o == null) {
      return "null";
    }
    if (o instanceof Number || o instanceof Boolean) {
      return o instanceof Double d ? String.format(Locale.ROOT, "%.3f", d) : o.toString();
    }
    if (o instanceof Map<?, ?> m) {
      StringBuilder sb = new StringBuilder("{");
      for (Map.Entry<?, ?> e : m.entrySet()) {
        if (sb.length() > 1) {
          sb.append(", ");
        }
        sb.append(json(String.valueOf(e.getKey()))).append(": ").append(json(e.getValue()));
      }
      return sb.append('}').toString();
    }
    if (o instanceof List<?> l) {
      StringBuilder sb = new StringBuilder("[");
      for (Object x : l) {
        if (sb.length() > 1) {
          sb.append(", ");
        }
        sb.append(json(x));
      }
      return sb.append(']').toString();
    }
    StringBuilder sb = new StringBuilder("\"");                     // control characters are escaped too (\n in errors)
    for (char ch : o.toString().toCharArray()) {
      switch (ch) {
        case '"' -> sb.append("\\\"");
        case '\\' -> sb.append("\\\\");
        case '\n' -> sb.append("\\n");
        case '\r' -> sb.append("\\r");
        case '\t' -> sb.append("\\t");
        default -> {
          if (ch < 0x20) {
            sb.append(String.format(Locale.ROOT, "\\u%04x", (int) ch));
          } else {
            sb.append(ch);
          }
        }
      }
    }
    return sb.append('"').toString();
  }

  synchronized void write(String status) throws Exception {
    Files.createDirectories(out);
    Map<String, Object> s = new LinkedHashMap<>();
    s.put("tool", "C7Probe (R1-C7 v1.2)");
    s.put("status", status);
    s.put("phases", phaseStatus);
    s.put("run_id", runId);
    s.put("bank", bank);
    s.put("verifier_id", verifierId);
    Map<String, Object> cfg = new LinkedHashMap<>();
    cfg.put("reg_n", regN);
    cfg.put("reg_warm", regWarm);
    cfg.put("fail_rounds", rounds);
    cfg.put("expired_rounds", expiredRounds);
    cfg.put("nonce_ttl_s", ttl);
    cfg.put("lock_max", lockMax);
    cfg.put("lock_base_s", lockBase);
    cfg.put("onboard_mode", onboardMode);
    cfg.put("life_rounds", lifeRounds);
    cfg.put("race_k", raceK);
    cfg.put("race_rounds", raceRounds);
    cfg.put("conc_users", concUsers);
    cfg.put("conc_threads", concThreads);
    cfg.put("restarts", restarts);
    cfg.put("restart_timeout_s", restartTimeout);
    s.put("config", cfg);
    s.put("java", System.getProperty("java.version") + " " + System.getProperty("java.vm.name"));
    Map<String, Object> st = new LinkedHashMap<>();
    for (Map.Entry<String, List<Double>> e : lat.entrySet()) {
      Map<String, Object> m = stats(e.getValue());
      int[] o = outcome.get(e.getKey());
      if (o != null) {
        m.put("as_expected", o[0]);
        m.put("unexpected", o[1]);
      }
      st.put(e.getKey(), m);
    }
    s.put("stats", st);
    s.put("extra", extra);
    Files.writeString(out.resolve("probe.json"), json(s) + "\n");
    Files.write(out.resolve("probe-raw.csv"), (String.join("\n",
        List.of("time,key,ms,outcome,detail")) + "\n" + String.join("\n", raw) + "\n").getBytes(StandardCharsets.UTF_8));
    int unexpected = outcome.values().stream().mapToInt(o -> o[1]).sum();
    System.out.println("== summary (ms: median / p95, n; unexpected)");
    for (Map.Entry<String, Object> e : st.entrySet()) {
      @SuppressWarnings("unchecked") Map<String, Object> m = (Map<String, Object>) e.getValue();
      System.out.printf(Locale.ROOT, "   %-36s %9s / %9s  n=%-4s%s%n", e.getKey(), fmt(m.get("median_ms")), fmt(m.get("p95_ms")),
          m.get("n"), m.containsKey("unexpected") ? "  unexpected=" + m.get("unexpected") : "");
    }
    System.out.println("   phases: " + phaseStatus);
    System.out.println("   results: " + out.resolve("probe.json") + " | unexpected in total: " + unexpected);
  }

  static String fmt(Object o) { return o instanceof Double d ? String.format(Locale.ROOT, "%.2f", d) : String.valueOf(o); }

  interface Phase { void run() throws Exception; }

  /** Every phase runs separately: an error in one phase is recorded and the following phases still run. */
  boolean runPhase(String name, Phase ph) {
    long t0 = System.nanoTime();
    try {
      ph.run();
      synchronized (this) {
        phaseStatus.put(name, String.format(Locale.ROOT, "ok (%.0f s)", msSince(t0) / 1000));
      }
      return true;
    } catch (Exception ex) {
      synchronized (this) {
        phaseStatus.put(name, "error: " + ex);
      }
      System.out.println("[fail] phase " + name + ": " + ex);
      return false;
    }
  }

  public static void main(String[] a) throws Exception {
    C7Probe p = new C7Probe();
    List<String> phases = List.of(env("C7_PHASES", "register,nipok,lockout,lifecycle,concurrency").split(","));
    boolean allOk = true;
    String host = URI.create(p.bank).getHost();
    try {
      String ip = InetAddress.getByName(host).getHostAddress();
      System.out.println("C7Probe v1.2: " + p.bank + " (" + host + " -> " + ip + "), verifier " + p.verifierId + ", run " + p.runId
          + ", phases " + phases);
      for (String ph : phases) {
        Phase run = switch (ph.strip()) {
          case "register" -> p::phaseRegister;
          case "nipok" -> p::phaseNipok;
          case "lockout" -> p::phaseLockout;
          case "lifecycle" -> p::phaseLifecycle;
          case "concurrency" -> p::phaseConcurrency;
          case "restart" -> p::phaseRestart;
          default -> throw new IllegalArgumentException("unknown phase: " + ph);
        };
        allOk &= p.runPhase(ph.strip(), run);
      }
    } catch (java.net.UnknownHostException ex) {
      allOk = false;
      System.out.println("[fail] " + host + " does not resolve: add the line '127.0.0.1 " + host + "' to /etc/hosts");
      p.phaseStatus.put("dns", "error: " + ex);
    } catch (Exception ex) {
      allOk = false;
      System.out.println("[fail] " + ex);
      p.phaseStatus.put("setup", "error: " + ex);
    }
    p.write(allOk ? "ok" : "error (xem phases)");
    int unexpected = p.outcome.values().stream().mapToInt(o -> o[1]).sum();
    System.exit(allOk && unexpected == 0 ? 0 : 1);
  }
}
