//CHECKSTYLE:OFF
package sample.audit;

import org.springframework.data.jpa.repository.JpaRepository;

public interface SecurityAuditRepository extends JpaRepository<SecurityAuditEntity, Long> {
  /** Bản ghi mới nhất (seq lớn nhất) — để seed prevHash + seq khi khởi động (chuỗi liên tục). */
  SecurityAuditEntity findTopByOrderBySeqDesc();
}
//CHECKSTYLE:ON
