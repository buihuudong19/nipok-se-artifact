//CHECKSTYLE:OFF
package sample.psu.store;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

public interface CustomerCredentialRepository extends JpaRepository<CustomerCredentialEntity, UUID> {
  Optional<CustomerCredentialEntity> findByCustomer_UsernameAndMethodAndEnabledTrue(String username, String method);

  /**
   * PSU-mTLS — tra ngược cert→PSU theo khóa công khai Ed25519 (b64url 32B raw) lưu ở
   * {@code credential}. {@code (method, credential)} định danh duy nhất một PSU đã enroll.
   */
  Optional<CustomerCredentialEntity> findByMethodAndCredentialAndEnabledTrue(String method, String credential);
}
//CHECKSTYLE:ON
