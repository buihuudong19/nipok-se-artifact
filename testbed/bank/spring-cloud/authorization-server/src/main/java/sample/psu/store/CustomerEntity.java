//CHECKSTYLE:OFF
package sample.psu.store;

import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** Customer identity (database customer_identity, separate). */
@Entity
@Table(name = "customer")
public class CustomerEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID customerId;

  @Column(nullable = false, unique = true, length = 128)
  private String username;

  @Column(nullable = false, length = 16)
  private String status = "ACTIVE";

  // Resource binding (STRIDE: elevation of privilege): customerId of the resource (MongoDB customer-service)
  // OWNED by this PSU. DIFFERENT from customerId (primary key of this table, PSU identity). Nullable - backward compatible:
  // an unmapped PSU -> the token carries NO customer_id claim -> the RS skips the binding (old flow unaffected).
  @Column(name = "bank_customer_id")
  private UUID bankCustomerId;

  protected CustomerEntity() { }

  public CustomerEntity(String username) { this.username = username; }

  public UUID getCustomerId() { return customerId; }
  public String getUsername() { return username; }
  public String getStatus() { return status; }
  public UUID getBankCustomerId() { return bankCustomerId; }
  public void setBankCustomerId(UUID bankCustomerId) { this.bankCustomerId = bankCustomerId; }
}
//CHECKSTYLE:ON
