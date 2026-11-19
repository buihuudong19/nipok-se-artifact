//CHECKSTYLE:OFF
package sample.psu.store;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

public interface CustomerCredentialRepository extends JpaRepository<CustomerCredentialEntity, UUID> {
  Optional<CustomerCredentialEntity> findByCustomer_UsernameAndMethodAndEnabledTrue(String username, String method);

  /**
   * PSU-mTLS - reverse lookup certificate -> PSU by the Ed25519 public key (b64url, 32 bytes raw) stored in
   * {@code credential}. {@code (method, credential)} uniquely identifies an enrolled PSU.
   */
  Optional<CustomerCredentialEntity> findByMethodAndCredentialAndEnabledTrue(String method, String credential);
}
//CHECKSTYLE:ON
