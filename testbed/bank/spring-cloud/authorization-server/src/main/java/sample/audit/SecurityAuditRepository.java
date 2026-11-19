//CHECKSTYLE:OFF
package sample.audit;

import org.springframework.data.jpa.repository.JpaRepository;

public interface SecurityAuditRepository extends JpaRepository<SecurityAuditEntity, Long> {
  /** Latest record (highest seq) - seeds prevHash + seq at start-up (continuous chain). */
  SecurityAuditEntity findTopByOrderBySeqDesc();
}
//CHECKSTYLE:ON
