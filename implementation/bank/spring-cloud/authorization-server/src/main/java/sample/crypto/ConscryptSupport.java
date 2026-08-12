package sample.crypto;

import java.security.Provider;
import java.security.Security;
import java.util.concurrent.atomic.AtomicReference;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Idempotent registration helper for the Conscrypt JCA provider.
 *
 * <p>Conscrypt loads a native shared library ({@code libconscrypt_openjdk_jni.so}) at first
 * use and exposes Ed25519 from version <strong>2.6-alpha</strong> onwards (GA 2.5.2 does
 * <em>not</em> include Ed25519). The provider is looked up reflectively so the rest of the
 * application can keep starting if the {@code org.conscrypt} dependency or its native
 * library is missing in the runtime image — callers receive a {@code false} return value
 * and can fall back to another strategy.
 *
 * <p>This class is thread-safe: registration is performed at most once across the JVM,
 * gated by a single CAS on the {@link State} cache.
 */
final class ConscryptSupport {

    static final String PROVIDER_NAME = "Conscrypt";

    private static final Logger LOG = LoggerFactory.getLogger(ConscryptSupport.class);

    /** Tri-state cache: null = not attempted, true/false = attempted with outcome. */
    private enum State { UNKNOWN, AVAILABLE, UNAVAILABLE }

    private static final AtomicReference<State> STATE = new AtomicReference<>(State.UNKNOWN);

    private ConscryptSupport() {
    }

    /**
     * Registers Conscrypt as a JCA provider if not yet registered. Safe to call repeatedly
     * and concurrently; the underlying work happens at most once.
     *
     * @return {@code true} if Conscrypt is now registered and available; {@code false} if
     *         the dependency or native library is missing
     */
    static boolean ensureRegistered() {
        State cached = STATE.get();
        if (cached == State.AVAILABLE) {
            return true;
        }
        if (cached == State.UNAVAILABLE) {
            return false;
        }
        synchronized (ConscryptSupport.class) {
            cached = STATE.get();
            if (cached != State.UNKNOWN) {
                return cached == State.AVAILABLE;
            }
            boolean ok = registerInternal();
            STATE.set(ok ? State.AVAILABLE : State.UNAVAILABLE);
            return ok;
        }
    }

    private static boolean registerInternal() {
        if (Security.getProvider(PROVIDER_NAME) != null) {
            LOG.debug("Conscrypt provider already registered");
            return true;
        }
        try {
            // Reflective so a missing org.conscrypt dependency does not break class-loading
            // of strategies that don't actually use Conscrypt.
            Class<?> cls = Class.forName("org.conscrypt.Conscrypt");
            Provider provider = (Provider) cls.getMethod("newProvider").invoke(null);
            Security.addProvider(provider);
            LOG.info("Registered Conscrypt JCA provider: {} {}", provider.getName(), provider.getVersionStr());
            return true;
        } catch (ClassNotFoundException e) {
            LOG.warn("Conscrypt class not on classpath — provider unavailable");
            return false;
        } catch (Throwable t) {
            LOG.warn("Failed to register Conscrypt provider: {}", t.toString());
            return false;
        }
    }
}
