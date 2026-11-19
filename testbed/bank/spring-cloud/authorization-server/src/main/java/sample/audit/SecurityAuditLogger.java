//CHECKSTYLE:OFF
package sample.audit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.annotation.PostConstruct;

/**
 * Tamper-evident, PERSISTENT security audit for every phase (PAR/authorize/consent/auth/lockout/
 * revoke/JARM/token/API). Every event = JSON {seq, ts, type, cid, ...details, prevHash, hash} with a
 * <b>hash chain</b> {@code hash = SHA-256(prevHash || canonical(event))} => changing/deleting one record BREAKS the chain.
 *
 * <p><b>Persistence:</b> besides the {@code SECURITY_AUDIT} log (shipped to WORM/SIEM), EVERY record is
 * PERSISTED in the table {@code security_audit_log} (append-only); at start-up {@code prevHash}+{@code seq} are seeded
 * from the record with the highest seq => the chain CONTINUES across restarts/replicas (no GENESIS reset each time).
 * Database error -> the log is still written (business flow not blocked). NOT used for token_issued (client_credentials hot path).
 */
@Component
public class SecurityAuditLogger {

  private static final Logger AUDIT = LoggerFactory.getLogger("SECURITY_AUDIT");
  private static final ObjectMapper JSON = new ObjectMapper();

  private final SecurityAuditRepository repo;
  private final AtomicLong seq = new AtomicLong();
  private volatile String prevHash = "GENESIS";
  private java.security.PrivateKey auditSignKey;   // Ed25519 signature over the hash (tamper-proof)

  public SecurityAuditLogger(SecurityAuditRepository repo) {
    this.repo = repo;
    initSigningKey();
  }

  /**
   * Audit signing key (Ed25519). Production: sign with Vault Transit/HSM and keep the public key in the SIEM for
   * verification. Here a key pair is generated at start-up and the public key is logged (enough to show tamper-proofing
   * within a session; verification across restarts needs the key persisted in Vault).
   */
  private void initSigningKey() {
    try {
      var kpg = java.security.KeyPairGenerator.getInstance("Ed25519");
      var kp = kpg.generateKeyPair();
      this.auditSignKey = kp.getPrivate();
      String pub = Base64.getUrlEncoder().withoutPadding().encodeToString(kp.getPublic().getEncoded());
      AUDIT.info("audit_signing_key Ed25519 pub(x509,b64url)={}", pub);   // stored by the SIEM to verify signatures
    } catch (Exception e) {
      AUDIT.warn("audit_signing_key_init_fail (signing disabled) {}", e.toString());
    }
  }

  private String sign(String hash) {
    if (auditSignKey == null) {
      return null;
    }
    try {
      var sig = java.security.Signature.getInstance("Ed25519");
      sig.initSign(auditSignKey);
      sig.update(hash.getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(sig.sign());
    } catch (Exception e) {
      return null;
    }
  }

  /** Seeds the chain from the database at start-up so that it does NOT break across restarts. */
  @PostConstruct
  void seedFromDb() {
    try {
      SecurityAuditEntity last = repo.findTopByOrderBySeqDesc();
      if (last != null) {
        prevHash = last.getHash();
        seq.set(last.getSeq() + 1);
        AUDIT.info("audit_chain_resumed from seq={} prevHash={}", last.getSeq(), prevHash);
      }
    } catch (Exception e) {
      AUDIT.warn("audit_seed_skip (database not ready?) {}", e.toString());
    }
  }

  /** Writes one audit event, chained by hash. cid = correlation id across phases (state/username/requestId). */
  public synchronized void record(String type, String cid, Map<String, Object> details) {
    try {
      long s = seq.getAndIncrement();
      String ts = Instant.now().toString();
      TreeMap<String, Object> ev = new TreeMap<>();   // TreeMap -> canonical form (sorted keys) for a stable hash
      ev.put("seq", s);
      ev.put("ts", ts);
      ev.put("type", type);
      ev.put("cid", cid == null ? "" : cid);
      if (details != null) {
        details.forEach((k, v) -> ev.put("d_" + k, v));
      }
      ev.put("prevHash", prevHash);
      String canonical = JSON.writeValueAsString(ev);          // keys already sorted (TreeMap)
      String hash = sha256(prevHash + canonical);
      ev.put("hash", hash);
      String sig = sign(hash);                                 // Ed25519 signature (tamper-proof)
      if (sig != null) {
        ev.put("sig", sig);
      }
      String detailJson = JSON.writeValueAsString(details == null ? Map.of() : details);
      String prev = prevHash;
      prevHash = hash;
      AUDIT.info("{}", JSON.writeValueAsString(ev));
      try {
        repo.save(new SecurityAuditEntity(s, ts, type, cid == null ? "" : cid, detailJson, prev, hash, sig));
      } catch (Exception dbe) {
        AUDIT.warn("audit_persist_fail seq={} type={} {}", s, type, dbe.toString());  // the log line remains
      }
    } catch (Exception e) {
      AUDIT.warn("audit_emit_fail type={} {}", type, e.toString());
    }
  }

  private static String sha256(String s) throws Exception {
    return Base64.getUrlEncoder().withoutPadding()
        .encodeToString(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
  }
}
//CHECKSTYLE:ON
