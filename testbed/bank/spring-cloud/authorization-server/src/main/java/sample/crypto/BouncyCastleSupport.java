package sample.crypto;

import java.security.Provider;
import java.security.Security;
import java.util.concurrent.atomic.AtomicReference;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Idempotent registration helper for the BouncyCastle JCA provider ({@code "BC"}).
 *
 * <p>The {@code bcprov} jar ships the {@code BouncyCastleProvider} which is registered
 * exactly once across the JVM. The reflective lookup keeps the rest of the application
 * functional if {@code org.bouncycastle:bcprov-jdk18on} is removed from the runtime image.
 */
final class BouncyCastleSupport {

    static final String PROVIDER_NAME = "BC";

    private static final Logger LOG = LoggerFactory.getLogger(BouncyCastleSupport.class);

    private enum State { UNKNOWN, AVAILABLE, UNAVAILABLE }

    private static final AtomicReference<State> STATE = new AtomicReference<>(State.UNKNOWN);

    private BouncyCastleSupport() {
    }

    static boolean ensureRegistered() {
        State cached = STATE.get();
        if (cached == State.AVAILABLE) {
            return true;
        }
        if (cached == State.UNAVAILABLE) {
            return false;
        }
        synchronized (BouncyCastleSupport.class) {
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
            LOG.debug("BouncyCastle provider already registered");
            return true;
        }
        try {
            Class<?> cls = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            Provider provider = (Provider) cls.getDeclaredConstructor().newInstance();
            Security.addProvider(provider);
            LOG.info("Registered BouncyCastle JCA provider: {} {}",
                provider.getName(), provider.getVersionStr());
            return true;
        } catch (ClassNotFoundException e) {
            LOG.warn("BouncyCastle class not on classpath - provider unavailable");
            return false;
        } catch (Throwable t) {
            LOG.warn("Failed to register BouncyCastle provider: {}", t.toString());
            return false;
        }
    }
}
