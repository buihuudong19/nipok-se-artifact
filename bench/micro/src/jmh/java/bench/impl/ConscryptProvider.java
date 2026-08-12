package bench.impl;

import org.conscrypt.Conscrypt;
import java.security.Security;

/**
 * BoringSSL qua Conscrypt (JCA provider). Native crypto, drop-in JCA.
 * Đáng chú ý: đây ĐÚNG là engine (BoringSSL) mà Envoy dùng cho TLS → liên hệ trực tiếp hệ thật.
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
            } catch (Throwable t) { /* để available() trả false */ }
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
