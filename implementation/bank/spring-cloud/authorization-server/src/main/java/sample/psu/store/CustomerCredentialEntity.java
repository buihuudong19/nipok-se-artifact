//CHECKSTYLE:OFF
package sample.psu.store;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

/**
 * Credential của Customer theo từng cơ chế (1 customer nhiều credential — switch/đồng thời).
 * PASSWORD: {@code credential} = chuỗi Argon2id PHC. Bất đối xứng (đợt sau): public key.
 */
@Entity
@Table(name = "customer_credential",
    uniqueConstraints = @UniqueConstraint(columnNames = {"customer_id", "method"}))
public class CustomerCredentialEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @ManyToOne(optional = false)
  @JoinColumn(name = "customer_id", nullable = false)
  private CustomerEntity customer;

  @Column(nullable = false, length = 32)
  private String method;          // AuthMethod.name()

  @Column(nullable = false)
  private boolean enabled = true;

  @Column(nullable = false, columnDefinition = "text")
  private String credential;      // PHC (password) hoặc public key (đợt sau)

  @Column(name = "cert_subject", length = 256)
  private String certSubject;

  @Column(name = "created_at", nullable = false)
  private Instant createdAt = Instant.now();

  protected CustomerCredentialEntity() { }

  public CustomerCredentialEntity(CustomerEntity customer, String method, String credential) {
    this.customer = customer;
    this.method = method;
    this.credential = credential;
  }

  public CustomerEntity getCustomer() { return customer; }
  public String getMethod() { return method; }
  public boolean isEnabled() { return enabled; }
  public String getCredential() { return credential; }
  public String getCertSubject() { return certSubject; }

  /** PSU-mTLS: lưu Subject DN của leaf cert (audit/đối soát; lookup vẫn theo pubkey ở credential). */
  public void setCertSubject(String certSubject) { this.certSubject = certSubject; }
}
//CHECKSTYLE:ON
