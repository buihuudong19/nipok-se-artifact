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
 * RAR (RFC 9396) - state and lifecycle of one consent.
 *
 * <p>A consent binds (PSU, TPP) to a set of fine-grained resources (table {@link ConsentResourceEntity}).
 * The token carries {@code consent_id} referring to this record; the RS enforces {@code r_req in resources(consent)}.
 *
 * <p>Indexes for the hot path: composite (psu_id, tpp_client_id, status) for the get-or-create query,
 * and (expires_at) for the expiry clean-up job.
 */
@Entity
@Table(name = "consent_metadata", indexes = {
    @Index(name = "idx_consent_psu_tpp_status", columnList = "psu_id,tpp_client_id,status"),
    @Index(name = "idx_consent_expires_at", columnList = "expires_at")
})
public class ConsentMetadataEntity {

  /** Consent lifecycle (simplified Open Banking lifecycle). */
  public static final String STATUS_AUTHORISED = "AUTHORISED";
  public static final String STATUS_REVOKED = "REVOKED";
  public static final String STATUS_EXPIRED = "EXPIRED";

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID consentId;

  @Column(name = "psu_id", nullable = false, length = 128)
  private String psuId;                 // authenticated PSU user name (= sub of the token)

  @Column(name = "tpp_client_id", nullable = false, length = 128)
  private String tppClientId;           // client_id of the TPP granted access

  @Column(nullable = false, length = 16)
  private String status = STATUS_AUTHORISED;

  @Column(length = 256)
  private String scope;                 // accompanying coarse scope (read/write)

  @Column(name = "created_at", nullable = false)
  private Instant createdAt = Instant.now();

  @Column(name = "authorised_at")
  private Instant authorisedAt;

  @Column(name = "expires_at", nullable = false)
  private Instant expiresAt;            // TTL - enforcement + sweeper

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
