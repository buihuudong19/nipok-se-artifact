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
 * RAR (RFC 9396) - one fine-grained resource bound in a consent.
 *
 * <p>One {@link ConsentMetadataEntity} has N of these records. The RS checks {@code resourceId == r_req}
 * by {@code resourceType}. Composite index (consent_id, resource_type, resource_id) +
 * INCLUDE actions => index-only membership query (optimised for load tests).
 */
@Entity
@Table(name = "consent_resources",
    uniqueConstraints = @UniqueConstraint(columnNames = {"consent_id", "resource_type", "resource_id"}),
    indexes = @Index(name = "idx_consent_res_lookup", columnList = "consent_id,resource_type,resource_id"))
public class ConsentResourceEntity {

  /** Resource type - routing key of the enforcement at the RS. */
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
