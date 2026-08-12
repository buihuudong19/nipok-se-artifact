//CHECKSTYLE:OFF
package sample.psu.store;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ConsentMetadataRepository extends JpaRepository<ConsentMetadataEntity, UUID> {

  /** Tìm consent đang hiệu lực (AUTHORISED + chưa hết hạn) của (PSU, TPP) — để get-or-create. */
  Optional<ConsentMetadataEntity> findFirstByPsuIdAndTppClientIdAndStatusAndExpiresAtAfterOrderByCreatedAtDesc(
      String psuId, String tppClientId, String status, Instant now);
}
//CHECKSTYLE:ON
