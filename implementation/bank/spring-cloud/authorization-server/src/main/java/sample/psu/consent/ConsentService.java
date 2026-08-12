//CHECKSTYLE:OFF
package sample.psu.consent;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import sample.psu.store.ConsentMetadataEntity;
import sample.psu.store.ConsentMetadataRepository;
import sample.psu.store.ConsentResourceEntity;
import sample.psu.store.ConsentResourceRepository;

/**
 * Task 2 (RAR / RFC 9396) — bắt và lưu Consent, là nguồn-sự-thật cho ràng buộc tài nguyên.
 *
 * <p><b>Chế độ auto-approve</b> ({@code app.consent.auto-approve}, mặc định {@code true}):
 * vì luồng e2e/benchmark của dự án KHÔNG có UI consent thật, AS tự "duyệt-tất-cả-tài-nguyên-PSU-sở-hữu"
 * (granted = owned) sau khi PSU xác thực (NIPoK/password). Đây CHÍNH là điểm tách khỏi UI production:
 * môi trường thật sẽ thay bằng màn hình consent chọn-lọc, còn benchmark giữ auto-approve để journey
 * headless chạy thông. Tắt: {@code app.consent.auto-approve=false} ⟹ KHÔNG tạo consent ⟹ token không
 * mang consent_id ⟹ RS fallback về customer_id (Task 1).
 *
 * <p>Get-or-create: tái dùng consent đang hiệu lực (AUTHORISED + chưa hết hạn) của (PSU, TPP) để
 * KHÔNG phình bảng dưới tải; chỉ tạo mới khi chưa có.
 */
@Service
public class ConsentService {

  /** Tham chiếu một tài nguyên hạt mịn (type + id), dùng cho cả input owned lẫn output granted. */
  public record ResourceRef(String type, String id, String actions) { }

  /** Kết quả: consent_id + tập tài nguyên đã cấp (để nhúng authorization_details vào token). */
  public record ConsentGrant(String consentId, List<ResourceRef> resources) { }

  private final ConsentMetadataRepository metadataRepo;
  private final ConsentResourceRepository resourceRepo;
  private final sample.audit.SecurityAuditLogger audit;   // Gap-3: audit consent grant/revoke
  private final boolean autoApprove;
  private final long ttlSeconds;

  public ConsentService(ConsentMetadataRepository metadataRepo,
                        ConsentResourceRepository resourceRepo,
                        sample.audit.SecurityAuditLogger audit,
                        @Value("${app.consent.auto-approve:true}") boolean autoApprove,
                        @Value("${app.consent.ttl-seconds:3600}") long ttlSeconds) {
    this.metadataRepo = metadataRepo;
    this.resourceRepo = resourceRepo;
    this.audit = audit;
    this.autoApprove = autoApprove;
    this.ttlSeconds = ttlSeconds;
  }

  /**
   * Trả consent đang hiệu lực cho (PSU, TPP); tạo mới (auto-approve) nếu chưa có.
   * @return ConsentGrant, hoặc {@code null} nếu auto-approve tắt hoặc PSU không sở hữu tài nguyên nào.
   */
  @Transactional
  public ConsentGrant getOrCreateConsent(String psuId, String tppClientId, String scope,
                                         List<ResourceRef> owned) {
    if (owned == null || owned.isEmpty()) {
      return null;                       // PSU chưa map tài nguyên ⟹ không có gì để ràng buộc
    }
    Instant now = Instant.now();

    // Tái dùng consent đang hiệu lực (tránh phình bảng dưới tải).
    var existing = metadataRepo
        .findFirstByPsuIdAndTppClientIdAndStatusAndExpiresAtAfterOrderByCreatedAtDesc(
            psuId, tppClientId, ConsentMetadataEntity.STATUS_AUTHORISED, now);
    if (existing.isPresent()) {
      ConsentMetadataEntity c = existing.get();
      return new ConsentGrant(c.getConsentId().toString(), toRefs(resourceRepo.findByConsentId(c.getConsentId())));
    }

    if (!autoApprove) {
      // Production: tới đây phải hiển thị consent UI cho PSU chọn. Môi trường này không có UI ⟹ bỏ.
      return null;
    }

    // Auto-approve: granted = owned. Lưu metadata + resources.
    Instant expiresAt = now.plus(ttlSeconds, ChronoUnit.SECONDS);
    ConsentMetadataEntity meta = metadataRepo.save(
        new ConsentMetadataEntity(psuId, tppClientId, scope, expiresAt));
    List<ResourceRef> granted = new ArrayList<>();
    for (ResourceRef r : owned) {
      resourceRepo.save(new ConsentResourceEntity(meta.getConsentId(), r.type(), r.id(), r.actions()));
      granted.add(r);
    }
    audit.record("CONSENT_GRANTED", psuId, java.util.Map.of(           // Gap-3: wire audit pha consent
        "consent_id", meta.getConsentId().toString(), "tpp", tppClientId,
        "resources", granted.size(), "ttl_s", ttlSeconds));
    return new ConsentGrant(meta.getConsentId().toString(), granted);
  }

  /**
   * Gap-4 — Thu hồi consent: set status=REVOKED + revoked_at. RS (qua status-check) sẽ từ chối token
   * tham chiếu consent này trong vòng cache-TTL. @return true nếu thu hồi thành công.
   */
  @Transactional
  public boolean revoke(String consentId, String actor) {
    try {
      var opt = metadataRepo.findById(java.util.UUID.fromString(consentId));
      if (opt.isEmpty()) {
        return false;
      }
      ConsentMetadataEntity c = opt.get();
      if (!ConsentMetadataEntity.STATUS_REVOKED.equals(c.getStatus())) {
        c.setStatus(ConsentMetadataEntity.STATUS_REVOKED);
        c.setRevokedAt(Instant.now());
        metadataRepo.save(c);
      }
      audit.record("CONSENT_REVOKED", c.getPsuId(), java.util.Map.of(
          "consent_id", consentId, "tpp", c.getTppClientId(), "by", actor == null ? "" : actor));
      return true;
    } catch (IllegalArgumentException e) {
      return false;                       // consentId không phải UUID hợp lệ
    }
  }

  /** Gap-4 — Trạng thái hiệu lực để RS cross-check revocation (active = AUTHORISED + chưa hết hạn). */
  @Transactional(readOnly = true)
  public boolean isActive(String consentId) {
    try {
      return metadataRepo.findById(java.util.UUID.fromString(consentId))
          .map(c -> ConsentMetadataEntity.STATUS_AUTHORISED.equals(c.getStatus())
              && c.getExpiresAt() != null && c.getExpiresAt().isAfter(Instant.now()))
          .orElse(false);
    } catch (IllegalArgumentException e) {
      return false;
    }
  }

  private static List<ResourceRef> toRefs(List<ConsentResourceEntity> rows) {
    List<ResourceRef> out = new ArrayList<>(rows.size());
    for (ConsentResourceEntity e : rows) {
      out.add(new ResourceRef(e.getResourceType(), e.getResourceId(), e.getActions()));
    }
    return out;
  }
}
//CHECKSTYLE:ON
