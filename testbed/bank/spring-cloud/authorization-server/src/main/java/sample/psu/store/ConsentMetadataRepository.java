//CHECKSTYLE:OFF
package sample.psu.store;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ConsentMetadataRepository extends JpaRepository<ConsentMetadataEntity, UUID> {

  /** Finds the valid consent (AUTHORISED and not expired) of (PSU, TPP) - for get-or-create. */
  Optional<ConsentMetadataEntity> findFirstByPsuIdAndTppClientIdAndStatusAndExpiresAtAfterOrderByCreatedAtDesc(
      String psuId, String tppClientId, String status, Instant now);
}
//CHECKSTYLE:ON
