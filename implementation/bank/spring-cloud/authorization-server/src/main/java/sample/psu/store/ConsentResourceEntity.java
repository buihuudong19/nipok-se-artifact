//CHECKSTYLE:OFF
package sample.psu.store;

import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

/**
 * Task 2 (RAR / RFC 9396) — một tài nguyên hạt mịn được ràng buộc trong một Consent.
 *
 * <p>1 {@link ConsentMetadataEntity} có N bản ghi này. RS kiểm {@code resourceId == r_req}
 * theo {@code resourceType}. Composite index (consent_id, resource_type, resource_id) +
 * INCLUDE actions ⟹ truy vấn thành viên index-only (tối ưu load-test).
 */
@Entity
@Table(name = "consent_resources",
    uniqueConstraints = @UniqueConstraint(columnNames = {"consent_id", "resource_type", "resource_id"}),
    indexes = @Index(name = "idx_consent_res_lookup", columnList = "consent_id,resource_type,resource_id"))
public class ConsentResourceEntity {

  /** Loại tài nguyên — khóa định tuyến enforcement ở RS. */
  public static final String TYPE_CUSTOMER_DATA = "openbanking_customer_data";
  public static final String TYPE_ACCOUNT = "account";

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @Column(name = "consent_id", nullable = false)
  private UUID consentId;

  @Column(name = "resource_type", nullable = false, length = 64)
  private String resourceType;

  @Column(name = "resource_id", nullable = false, length = 128)
  private String resourceId;

  @Column(length = 64)
  private String actions = "read";

  protected ConsentResourceEntity() { }

  public ConsentResourceEntity(UUID consentId, String resourceType, String resourceId, String actions) {
    this.consentId = consentId;
    this.resourceType = resourceType;
    this.resourceId = resourceId;
    this.actions = actions;
  }

  public UUID getId() { return id; }
  public UUID getConsentId() { return consentId; }
  public String getResourceType() { return resourceType; }
  public String getResourceId() { return resourceId; }
  public String getActions() { return actions; }
}
//CHECKSTYLE:ON
