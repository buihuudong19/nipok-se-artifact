//CHECKSTYLE:OFF
package sample.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

/**
 * PERSISTENT audit record (append-only) storing the hash chain, so that it survives restarts/replicas.
 * The prevHash of the next record is seeded at start-up from the {@code hash} of the record with the highest seq.
 */
@Entity
@Table(name = "security_audit_log", indexes = @Index(name = "idx_audit_seq", columnList = "seq"))
public class SecurityAuditEntity {

  @Id
  @Column(nullable = false)
  private long seq;                 // continuous sequence number (source of truth of the chain)

  @Column(nullable = false, length = 40)
  private String ts;

  @Column(nullable = false, length = 64)
  private String type;

  @Column(length = 256)
  private String cid;

  @Column(columnDefinition = "text")
  private String detail;            // JSON of the d_* fields

  @Column(name = "prev_hash", nullable = false, length = 64)
  private String prevHash;

  @Column(nullable = false, length = 64)
  private String hash;

  // Ed25519 signature over the hash. The hash chain makes changes evident (tamper-evident); the signature prevents
  // wholesale FORGERY (tamper-proof): an attacker rewriting the whole table cannot re-sign without the private key.
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
