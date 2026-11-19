package bench.c7;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Security-cost ablation (Reviewer 1, Comment 7): copy of {@code SecurityAuditLogger.record} (auth-server,
 * {@code sample/audit/SecurityAuditLogger.java}, md5 of the measured file f514e04d...) for
 * {@link EnvelopeAblationBenchmark#as_audit_record}. Measurement tool only; the service code is unchanged.
 *
 * <p><b>Same as the real code:</b> {@code synchronized} method; the event is a {@code TreeMap} (keys in alphabetical
 * order) with seq, ts, type, cid, the {@code d_...} fields and prevHash; canonical JSON from one shared
 * {@code ObjectMapper} (Jackson, same version as in the auth-server bootJar, see build.gradle); hash =
 * base64url(SHA-256(prevHash || canonical)); Ed25519 signature over the hash string with
 * {@code Signature.getInstance("Ed25519")} and a key from {@code KeyPairGenerator.getInstance("Ed25519")}, i.e. the
 * default JCA provider (the auth-server only adds Conscrypt and BouncyCastle with {@code Security.addProvider}, after
 * SunEC); hash and sig added to the event; JSON of the details; hash chain (prevHash = hash); the JSON string of the
 * whole event passed to {@code AUDIT.info("{}", ...)} (Jackson runs before the logger call, so it is included).
 *
 * <p><b>Left out:</b> writing the log line ({@code AUDIT.info}) and the database insert ({@code repo.save} into
 * security_audit_log, also inside the lock). Both are part of the {@code POST /psu/auth} stage measured at the gateway
 * by the hops step.
 *
 * <p><b>Where it is called (from the code):</b> {@code PSU_AUTH} once per proof or signature check of the six public-key
 * mechanisms (NipokAuthenticationProvider, SchnorrController, EdDsa-, PrivateKeyJwt-, MlDsa-, MtlsAuthenticationProvider);
 * Password writes no {@code PSU_AUTH} (only {@code PSU_LOCKOUT} on lockout); {@code CONSENT_GRANTED} only when a new
 * consent is created (a valid consent is reused, TTL 3600 s).
 */
final class AuditLoggerCopy {

  private static final ObjectMapper JSON = new ObjectMapper();

  private final AtomicLong seq = new AtomicLong();
  private volatile String prevHash = "GENESIS";
  private final PrivateKey auditSignKey;
  private final PublicKey auditPublicKey;                             // only for the signature check of the correctness gate
  final String signProvider;                                          // JCA provider actually used for signing (printed by the gate)

  AuditLoggerCopy() throws Exception {
    KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();   // as initSigningKey()
    auditSignKey = kp.getPrivate();
    auditPublicKey = kp.getPublic();
    Signature probe = Signature.getInstance("Ed25519");
    probe.initSign(auditSignKey);                                     // the provider is chosen at initSign
    signProvider = probe.getProvider().getName();
  }

  /** As {@code SecurityAuditLogger.sign}: a new Signature at every call, error => null. */
  private String sign(String hash) {
    try {
      Signature sig = Signature.getInstance("Ed25519");
      sig.initSign(auditSignKey);
      sig.update(hash.getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(sig.sign());
    } catch (Exception e) {
      return null;
    }
  }

  /** The strings the real code creates in one record (JMH consumes the whole record; the correctness gate checks it). */
  record Out(String prev, String canonical, String hash, String sig, String detailJson, String logLine) { }

  /** Body of {@code record(type, cid, details)} of the real code, without {@code AUDIT.info} and {@code repo.save}. */
  synchronized Out record(String type, String cid, Map<String, Object> details) throws Exception {
    long s = seq.getAndIncrement();
    String ts = Instant.now().toString();
    TreeMap<String, Object> ev = new TreeMap<>();
    ev.put("seq", s);
    ev.put("ts", ts);
    ev.put("type", type);
    ev.put("cid", cid == null ? "" : cid);
    if (details != null) {
      details.forEach((k, v) -> ev.put("d_" + k, v));
    }
    ev.put("prevHash", prevHash);
    String canonical = JSON.writeValueAsString(ev);
    String hash = sha256(prevHash + canonical);
    ev.put("hash", hash);
    String sig = sign(hash);
    if (sig != null) {
      ev.put("sig", sig);
    }
    String detailJson = JSON.writeValueAsString(details == null ? Map.of() : details);
    String prev = prevHash;
    prevHash = hash;
    String logLine = JSON.writeValueAsString(ev);                     // argument of AUDIT.info("{}", ...)
    return new Out(prev, canonical, hash, sig, detailJson, logLine);
  }

  /** Only the Ed25519 signature of one record (share of the signature in as_audit_record). */
  String signOnly(String hash) {
    return sign(hash);
  }

  static String sha256(String s) throws Exception {
    return Base64.getUrlEncoder().withoutPadding()
        .encodeToString(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
  }

  /**
   * Correctness gate (outside the measurement): hash = SHA-256(prevHash || canonical); the next record chains to the previous
   * one; the signature verifies with the public key; canonical in key order, without hash/sig; the log line has hash and sig;
   * signing the same hash again gives the same signature (deterministic Ed25519). Failure => exception, nothing is measured.
   */
  void gate(Map<String, Object> details) throws Exception {
    Out a = record("PSU_AUTH", "nipok-1", details);
    Out b = record("PSU_AUTH", "nipok-1", details);
    check(a.hash().equals(sha256(a.prev() + a.canonical())), "hash differs from SHA-256(prevHash || canonical)");
    check(b.prev().equals(a.hash()) && b.hash().equals(sha256(a.hash() + b.canonical())), "hash chain broken");
    check(a.sig() != null, "audit record could not be signed (provider " + signProvider + ")");
    Signature v = Signature.getInstance("Ed25519");
    v.initVerify(auditPublicKey);
    v.update(a.hash().getBytes(StandardCharsets.UTF_8));
    check(v.verify(Base64.getUrlDecoder().decode(a.sig())), "audit signature does not verify");
    check(a.sig().equals(signOnly(a.hash())), "signing the same hash again must give the same signature (deterministic Ed25519)");
    check(a.canonical().startsWith("{\"cid\":\"nipok-1\",\"d_") && a.canonical().contains("\"prevHash\":\"" + a.prev() + "\"")
        && !a.canonical().contains("\"hash\"") && !a.canonical().contains("\"sig\""), "canonical has the wrong form: " + a.canonical());
    check(a.logLine().contains("\"hash\":\"" + a.hash() + "\"") && a.logLine().contains("\"sig\":\"" + a.sig() + "\""),
        "log line without hash or sig");
    System.out.printf("R1-C7 audit: signing provider %s, canonical %d characters, log line %d characters, details %d characters%n",
        signProvider, a.canonical().length(), a.logLine().length(), a.detailJson().length());
  }

  private static void check(boolean ok, String what) {
    if (!ok) {
      throw new IllegalStateException("R1-C7 correctness gate (audit) failed: " + what);
    }
  }
}
