//CHECKSTYLE:OFF
package sample.psu.store;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

public interface CustomerRepository extends JpaRepository<CustomerEntity, UUID> {
  Optional<CustomerEntity> findByUsername(String username);
  boolean existsByUsername(String username);
}
//CHECKSTYLE:ON
