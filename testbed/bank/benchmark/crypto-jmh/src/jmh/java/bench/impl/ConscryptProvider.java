package bench.impl;

import org.conscrypt.Conscrypt;
import java.security.Security;

/**
 * BoringSSL through Conscrypt (JCA provider). Native crypto, drop-in JCA.
 * Notably, this is EXACTLY the engine (BoringSSL) used by Envoy for TLS -> direct link to the real system.
 */
public final class ConscryptProvider extends JcaProvider {

    private static volatile boolean registered = false;

    public ConscryptProvider() {
        super("Conscrypt");
        ensureRegistered();
    }

    private static synchronized void ensureRegistered() {
        if (!registered) {
            try {
                if (Security.getProvider("Conscrypt") == null) {
                    Security.addProvider(Conscrypt.newProvider());
                }
                registered = true;
            } catch (Throwable t) { /* available() then returns false */ }
        }
    }

    @Override public String id() { return "conscrypt-boringssl"; }

    @Override public boolean available() {
        try {
            if (!Conscrypt.isAvailable()) return false;
            ensureRegistered();
            return super.available();
        } catch (Throwable t) { return false; }
    }
}
