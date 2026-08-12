//CHECKSTYLE:OFF
package sample.psu.store;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ConsentResourceRepository extends JpaRepository<ConsentResourceEntity, UUID> {
  List<ConsentResourceEntity> findByConsentId(UUID consentId);
}
//CHECKSTYLE:ON
