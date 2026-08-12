package sample.crypto;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Registry / factory for {@link Ed25519SigningStrategy} implementations.
 *
 * <p>This is the single entry point used by the Spring configuration to materialise a
 * strategy from the {@code app.ed25519.provider} configuration property. The internal
 * registry is keyed by the stable {@code id} string and uses {@link Supplier}s so a
 * strategy that fails to construct on a given platform does not pollute the registry.
 *
 * <h2>Adding a new backend (Task 2)</h2>
 * <p>Implement {@link Ed25519SigningStrategy} (typically in a new class under this
 * package) and register it in {@link #BUILDERS} with its {@code impl} id from the
 * benchmark harness. Nothing else needs to change.
 */
public final class Ed25519SigningStrategies {

    public static final String JCA_SUNEC                  = "jca-sunec";
    public static final String CONSCRYPT_BORINGSSL        = "conscrypt-boringssl";
    public static final String BC_JCA                     = "bc-jca";
    public static final String BC_LIGHTWEIGHT             = "bc-lightweight";
    public static final String TINK                       = "tink";
    public static final String LIBSODIUM_LAZYSODIUM_JNA   = "libsodium-lazysodium-jna";
    public static final String LIBSODIUM_PANAMA_FFM       = "libsodium-panama-ffm";

    /**
     * Ngầm định khi {@code app.ed25519.provider} không được thiết lập. Conscrypt/BoringSSL
     * được chọn vì hiệu năng native vượt trội mà JMH benchmark đo được — đây cũng đúng engine
     * mà Envoy dùng cho TLS, nên auth-server và mesh chia sẻ cùng một thư viện crypto.
     */
    public static final String DEFAULT_ID = CONSCRYPT_BORINGSSL;

    /**
     * Lưới an toàn cuối — nếu {@link #DEFAULT_ID} không khả dụng tại runtime (ví dụ
     * jar Conscrypt bị bóc khỏi image), strategy này luôn dùng được vì là JDK built-in.
     * Đảm bảo auth-server boot thành công ngay cả khi Conscrypt fail nạp native.
     */
    public static final String SAFETY_FALLBACK_ID = JCA_SUNEC;

    private static final Logger LOG = LoggerFactory.getLogger(Ed25519SigningStrategies.class);

    private static final Map<String, Supplier<Ed25519SigningStrategy>> BUILDERS = new LinkedHashMap<>();
    static {
        BUILDERS.put(JCA_SUNEC,           () -> new JcaEd25519SigningStrategy(JCA_SUNEC, "SunEC"));
        BUILDERS.put(CONSCRYPT_BORINGSSL,  Ed25519SigningStrategies::createConscryptStrategy);
        BUILDERS.put(BC_JCA,              Ed25519SigningStrategies::createBcJcaStrategy);
        BUILDERS.put(BC_LIGHTWEIGHT,       BcLightweightEd25519SigningStrategy::new);
        BUILDERS.put(TINK,                 TinkEd25519SigningStrategy::new);
        BUILDERS.put(LIBSODIUM_LAZYSODIUM_JNA, LibsodiumLazysodiumEd25519SigningStrategy::new);
        BUILDERS.put(LIBSODIUM_PANAMA_FFM,     LibsodiumPanamaFfmEd25519SigningStrategy::new);
    }

    private Ed25519SigningStrategies() {
    }

    /** The set of registered strategy ids in declaration order. */
    public static Set<String> registeredIds() {
        return Set.copyOf(BUILDERS.keySet());
    }

    /**
     * Resolves the strategy with a two-tier fallback:
     * <ol>
     *   <li>the requested id (or {@link #DEFAULT_ID} if blank);</li>
     *   <li>{@link #SAFETY_FALLBACK_ID} (always-available JDK SunEC) if step 1 fails.</li>
     * </ol>
     * Guarantees the auth-server boots even with a misconfigured property or a runtime
     * environment that cannot load the default (Conscrypt) native library.
     */
    public static Ed25519SigningStrategy createOrDefault(String id) {
        String requested = (id == null || id.isBlank()) ? DEFAULT_ID : id;
        try {
            Ed25519SigningStrategy strategy = create(requested);
            if (strategy.available()) {
                return strategy;
            }
            LOG.warn("Ed25519 strategy '{}' loaded but reports !available — falling back to '{}'",
                requested, SAFETY_FALLBACK_ID);
        } catch (Exception e) {
            LOG.warn("Ed25519 strategy '{}' failed to initialise ({}) — falling back to '{}'",
                requested, e.getMessage(), SAFETY_FALLBACK_ID);
        }
        if (requested.equals(SAFETY_FALLBACK_ID)) {
            // Even the safety net failed — nothing left to try.
            throw new Ed25519CryptoException(
                "Safety-net Ed25519 strategy '" + SAFETY_FALLBACK_ID + "' unavailable");
        }
        return create(SAFETY_FALLBACK_ID);
    }

    /**
     * Creates the strategy for the given id without any fallback.
     *
     * @throws IllegalArgumentException if no strategy is registered for the id
     * @throws Ed25519CryptoException   if the strategy is registered but cannot be instantiated
     */
    public static Ed25519SigningStrategy create(String id) {
        Supplier<Ed25519SigningStrategy> builder = BUILDERS.get(id);
        if (builder == null) {
            throw new IllegalArgumentException("Unknown Ed25519 strategy id '" + id
                + "'. Registered: " + BUILDERS.keySet());
        }
        return builder.get();
    }

    private static Ed25519SigningStrategy createConscryptStrategy() {
        if (!ConscryptSupport.ensureRegistered()) {
            throw new Ed25519CryptoException(
                "Conscrypt provider unavailable (missing dependency or native library). "
                    + "Ed25519 requires conscrypt-openjdk-uber:2.6-alpha or newer.");
        }
        return new JcaEd25519SigningStrategy(CONSCRYPT_BORINGSSL, ConscryptSupport.PROVIDER_NAME);
    }

    private static Ed25519SigningStrategy createBcJcaStrategy() {
        if (!BouncyCastleSupport.ensureRegistered()) {
            throw new Ed25519CryptoException(
                "BouncyCastle provider unavailable (org.bouncycastle:bcprov-jdk18on missing on classpath).");
        }
        return new JcaEd25519SigningStrategy(BC_JCA, BouncyCastleSupport.PROVIDER_NAME);
    }
}
