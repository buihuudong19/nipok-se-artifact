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
 * G6 + Gap-3 — Audit BẢO MẬT tamper-evident, BỀN VỮNG cho mọi pha (PAR/authorize/consent/auth/lockout/
 * revoke/JARM/token/API). Mỗi sự kiện = JSON {seq, ts, type, cid, ...details, prevHash, hash} với
 * <b>hash-chain</b> {@code hash = SHA-256(prevHash ‖ canonical(event))} ⟹ sửa/xoá 1 bản ghi GÃY chuỗi.
 *
 * <p><b>Gap-3 (bền vững):</b> ngoài log {@code SECURITY_AUDIT} (ship WORM/SIEM), MỖI bản ghi được
 * PERSIST xuống bảng {@code security_audit_log} (append-only); khi khởi động seed {@code prevHash}+{@code seq}
 * từ bản ghi seq lớn nhất ⟹ chuỗi LIÊN TỤC qua restart/multi-replica (KHÔNG reset GENESIS mỗi lần).
 * DB lỗi → vẫn ghi log (không chặn nghiệp vụ). KHÔNG dùng cho token_issued (hot-path client_credentials).
 */
@Component
public class SecurityAuditLogger {

  private static final Logger AUDIT = LoggerFactory.getLogger("SECURITY_AUDIT");
  private static final ObjectMapper JSON = new ObjectMapper();

  private final SecurityAuditRepository repo;
  private final AtomicLong seq = new AtomicLong();
  private volatile String prevHash = "GENESIS";
  private java.security.PrivateKey auditSignKey;   // Task 5 — ký Ed25519 trên hash (tamper-proof)

  public SecurityAuditLogger(SecurityAuditRepository repo) {
    this.repo = repo;
    initSigningKey();
  }

  /**
   * Task 5 — khóa ký audit (Ed25519). Production: KÝ bằng Vault Transit/HSM + giữ public key ở SIEM để
   * verify. Ở đây sinh keypair tại khởi động + log public key (đủ chứng minh tamper-proof trong phiên;
   * verify xuyên-restart cần persist khóa qua Vault — ghi chú).
   */
  private void initSigningKey() {
    try {
      var kpg = java.security.KeyPairGenerator.getInstance("Ed25519");
      var kp = kpg.generateKeyPair();
      this.auditSignKey = kp.getPrivate();
      String pub = Base64.getUrlEncoder().withoutPadding().encodeToString(kp.getPublic().getEncoded());
      AUDIT.info("audit_signing_key Ed25519 pub(x509,b64url)={}", pub);   // SIEM lưu để verify chữ ký
    } catch (Exception e) {
      AUDIT.warn("audit_signing_key_init_fail (ký bị tắt) {}", e.toString());
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

  /** Gap-3 — seed chuỗi từ DB khi khởi động để KHÔNG đứt qua restart. */
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
      AUDIT.warn("audit_seed_skip (DB chưa sẵn sàng?) {}", e.toString());
    }
  }

  /** Ghi 1 sự kiện audit, nối hash-chain. cid = correlation-id xuyên pha (state/username/requestId). */
  public synchronized void record(String type, String cid, Map<String, Object> details) {
    try {
      long s = seq.getAndIncrement();
      String ts = Instant.now().toString();
      TreeMap<String, Object> ev = new TreeMap<>();   // TreeMap → canonical (key sorted) cho hash ổn định
      ev.put("seq", s);
      ev.put("ts", ts);
      ev.put("type", type);
      ev.put("cid", cid == null ? "" : cid);
      if (details != null) {
        details.forEach((k, v) -> ev.put("d_" + k, v));
      }
      ev.put("prevHash", prevHash);
      String canonical = JSON.writeValueAsString(ev);          // keys đã sorted (TreeMap)
      String hash = sha256(prevHash + canonical);
      ev.put("hash", hash);
      String sig = sign(hash);                                 // Task 5 — chữ ký Ed25519 (tamper-proof)
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
        AUDIT.warn("audit_persist_fail seq={} type={} {}", s, type, dbe.toString());  // log vẫn còn
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
