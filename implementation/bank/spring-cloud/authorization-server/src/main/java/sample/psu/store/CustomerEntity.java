//CHECKSTYLE:OFF
package sample.psu.store;

import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** Định danh Customer (DB customer_identity, độc lập). */
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

  // Task 1 (STRIDE E — resource-binding): customerId của tài nguyên (MongoDB customer-service) mà
  // PSU này SỞ HỮU. KHÁC customerId (PK của bảng này, định danh PSU). Nullable — backward-compat:
  // PSU chưa map → token KHÔNG mang claim customer_id → RS bỏ qua binding (không phá luồng cũ).
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
