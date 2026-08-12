//CHECKSTYLE:OFF
package sample.psu.store;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

/**
 * Task 2 (RAR / RFC 9396) — trạng thái + vòng đời của một Consent.
 *
 * <p>Một consent gắn (PSU, TPP) với tập tài nguyên hạt mịn (bảng {@link ConsentResourceEntity}).
 * Token mang {@code consent_id} tham chiếu bản ghi này; RS enforce {@code r_req ∈ resources(consent)}.
 *
 * <p>Index tối ưu hot-path: composite (psu_id, tpp_client_id, status) cho truy vấn get-or-create,
 * và (expires_at) cho job dọn hết hạn.
 */
@Entity
@Table(name = "consent_metadata", indexes = {
    @Index(name = "idx_consent_psu_tpp_status", columnList = "psu_id,tpp_client_id,status"),
    @Index(name = "idx_consent_expires_at", columnList = "expires_at")
})
public class ConsentMetadataEntity {

  /** Vòng đời consent (Open Banking lifecycle rút gọn). */
  public static final String STATUS_AUTHORISED = "AUTHORISED";
  public static final String STATUS_REVOKED = "REVOKED";
  public static final String STATUS_EXPIRED = "EXPIRED";

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID consentId;

  @Column(name = "psu_id", nullable = false, length = 128)
  private String psuId;                 // username PSU đã xác thực (= sub của token)

  @Column(name = "tpp_client_id", nullable = false, length = 128)
  private String tppClientId;           // client_id của TPP được cấp

  @Column(nullable = false, length = 16)
  private String status = STATUS_AUTHORISED;

  @Column(length = 256)
  private String scope;                 // scope cấp-loại đi kèm (read/write)

  @Column(name = "created_at", nullable = false)
  private Instant createdAt = Instant.now();

  @Column(name = "authorised_at")
  private Instant authorisedAt;

  @Column(name = "expires_at", nullable = false)
  private Instant expiresAt;            // TTL — enforcement + sweeper

  @Column(name = "revoked_at")
  private Instant revokedAt;

  @Column(nullable = false)
  private int version = 1;              // cache-invalidation / optimistic versioning

  protected ConsentMetadataEntity() { }

  public ConsentMetadataEntity(String psuId, String tppClientId, String scope, Instant expiresAt) {
    this.psuId = psuId;
    this.tppClientId = tppClientId;
    this.scope = scope;
    this.expiresAt = expiresAt;
    this.authorisedAt = Instant.now();
  }

  public UUID getConsentId() { return consentId; }
  public String getPsuId() { return psuId; }
  public String getTppClientId() { return tppClientId; }
  public String getStatus() { return status; }
  public void setStatus(String status) { this.status = status; }
  public String getScope() { return scope; }
  public Instant getCreatedAt() { return createdAt; }
  public Instant getAuthorisedAt() { return authorisedAt; }
  public Instant getExpiresAt() { return expiresAt; }
  public Instant getRevokedAt() { return revokedAt; }
  public void setRevokedAt(Instant revokedAt) { this.revokedAt = revokedAt; }
  public int getVersion() { return version; }
}
//CHECKSTYLE:ON
