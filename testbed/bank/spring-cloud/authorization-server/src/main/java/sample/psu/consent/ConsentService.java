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
 * RAR (RFC 9396) - captures and stores the consent, the source of truth for the resource binding.
 *
 * <p><b>Auto-approve mode</b> ({@code app.consent.auto-approve}, default {@code true}):
 * the end-to-end and benchmark journeys of the project have NO real consent UI, so the AS approves all resources
 * owned by the PSU (granted = owned) after the PSU authenticates (NIPoK/password). This is exactly where the testbed
 * departs from a production UI: a real deployment shows a selective consent screen, while the benchmark keeps
 * auto-approve so that the headless journey completes. Disabled with {@code app.consent.auto-approve=false} => NO
 * consent is created => the token carries no consent_id => the RS falls back to customer_id.
 *
 * <p>Get-or-create: reuses the valid consent (AUTHORISED and not expired) of (PSU, TPP), so that
 * the table does NOT grow under load; a new one is created only when none exists.
 */
@Service
public class ConsentService {

  /** Reference to one fine-grained resource (type + id), used for both the owned input and the granted output. */
  public record ResourceRef(String type, String id, String actions) { }

  /** Result: consent_id + set of granted resources (embedded as authorization_details in the token). */
  public record ConsentGrant(String consentId, List<ResourceRef> resources) { }

  private final ConsentMetadataRepository metadataRepo;
  private final ConsentResourceRepository resourceRepo;
  private final sample.audit.SecurityAuditLogger audit;   // audit of consent grant/revoke
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
   * Returns the valid consent of (PSU, TPP); creates one (auto-approve) if none exists.
   * @return ConsentGrant, or {@code null} if auto-approve is disabled or the PSU owns no resource.
   */
  @Transactional
  public ConsentGrant getOrCreateConsent(String psuId, String tppClientId, String scope,
                                         List<ResourceRef> owned) {
    if (owned == null || owned.isEmpty()) {
      return null;                       // PSU not mapped to resources => nothing to bind
    }
    Instant now = Instant.now();

    // Reuse the valid consent (avoids table growth under load).
    var existing = metadataRepo
        .findFirstByPsuIdAndTppClientIdAndStatusAndExpiresAtAfterOrderByCreatedAtDesc(
            psuId, tppClientId, ConsentMetadataEntity.STATUS_AUTHORISED, now);
    if (existing.isPresent()) {
      ConsentMetadataEntity c = existing.get();
      return new ConsentGrant(c.getConsentId().toString(), toRefs(resourceRepo.findByConsentId(c.getConsentId())));
    }

    if (!autoApprove) {
      // Production: a consent UI would be shown here for the PSU to choose. This environment has no UI => skipped.
      return null;
    }

    // Auto-approve: granted = owned. Metadata and resources are stored.
    Instant expiresAt = now.plus(ttlSeconds, ChronoUnit.SECONDS);
    ConsentMetadataEntity meta = metadataRepo.save(
        new ConsentMetadataEntity(psuId, tppClientId, scope, expiresAt));
    List<ResourceRef> granted = new ArrayList<>();
    for (ResourceRef r : owned) {
      resourceRepo.save(new ConsentResourceEntity(meta.getConsentId(), r.type(), r.id(), r.actions()));
      granted.add(r);
    }
    audit.record("CONSENT_GRANTED", psuId, java.util.Map.of(           // audit of the consent phase
        "consent_id", meta.getConsentId().toString(), "tpp", tppClientId,
        "resources", granted.size(), "ttl_s", ttlSeconds));
    return new ConsentGrant(meta.getConsentId().toString(), granted);
  }

  /**
   * Consent revocation: sets status=REVOKED and revoked_at. The RS (through the status check) rejects tokens
   * referring to this consent within the cache TTL. @return true if the revocation succeeded.
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
      return false;                       // consentId is not a valid UUID
    }
  }

  /** Validity status for the revocation cross-check of the RS (active = AUTHORISED and not expired). */
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
