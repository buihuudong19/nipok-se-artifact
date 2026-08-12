package bench.impl;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;

/** BouncyCastle qua JCA provider ("BC"). Đo overhead khung JCA so với bc-lightweight. */
public final class BcJcaProvider extends JcaProvider {

    private static volatile boolean registered = false;

    public BcJcaProvider() {
        super("BC");
        ensureRegistered();
    }

    private static synchronized void ensureRegistered() {
        if (!registered) {
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            registered = true;
        }
    }

    @Override public String id() { return "bc-jca"; }

    @Override public boolean available() {
        try { ensureRegistered(); return super.available(); }
        catch (Throwable t) { return false; }
    }
}
