//CHECKSTYLE:OFF
package sample.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

/**
 * Gap-3 — Bản ghi audit BỀN VỮNG (append-only) lưu cả hash-chain để sống sót qua restart/multi-replica.
 * prevHash của bản ghi kế tiếp được seed từ {@code hash} của bản ghi seq lớn nhất khi khởi động.
 */
@Entity
@Table(name = "security_audit_log", indexes = @Index(name = "idx_audit_seq", columnList = "seq"))
public class SecurityAuditEntity {

  @Id
  @Column(nullable = false)
  private long seq;                 // số thứ tự liên tục (nguồn-sự-thật của chuỗi)

  @Column(nullable = false, length = 40)
  private String ts;

  @Column(nullable = false, length = 64)
  private String type;

  @Column(length = 256)
  private String cid;

  @Column(columnDefinition = "text")
  private String detail;            // JSON các field d_*

  @Column(name = "prev_hash", nullable = false, length = 64)
  private String prevHash;

  @Column(nullable = false, length = 64)
  private String hash;

  // Task 5 — chữ ký Ed25519 trên hash. Hash-chain chống SỬA (tamper-evident); chữ ký chống GIẢ MẠO
  // toàn bộ (tamper-proof): attacker viết lại cả bảng vẫn KHÔNG ký lại được nếu không có private key.
  @Column(length = 96)
  private String sig;

  protected SecurityAuditEntity() { }

  public SecurityAuditEntity(long seq, String ts, String type, String cid,
                             String detail, String prevHash, String hash, String sig) {
    this.seq = seq;
    this.ts = ts;
    this.type = type;
    this.cid = cid;
    this.detail = detail;
    this.prevHash = prevHash;
    this.hash = hash;
    this.sig = sig;
  }

  public long getSeq() { return seq; }
  public String getHash() { return hash; }
  public String getPrevHash() { return prevHash; }
  public String getSig() { return sig; }
}
//CHECKSTYLE:ON
