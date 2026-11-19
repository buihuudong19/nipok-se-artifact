package bench;

import bench.impl.*;
import java.util.List;

/** Registry - maps id -> implementation. Implementations are added/removed here. */
public final class Providers {

    /** Display order; also the default @Param set of the benchmark. */
    public static final List<String> IDS = List.of(
        "jca-sunec",                  // baseline: JDK built-in (SunEC, pure-Java)
        "bc-lightweight",             // BouncyCastle lightweight API (the fastest BC variant)
        "bc-jca",                     // BouncyCastle through the JCA provider (framework overhead)
        "tink",                       // Google Tink (subtle Ed25519, pure-Java)
        "libsodium-lazysodium-jna",   // libsodium through JNA (high FFI overhead)
        "libsodium-panama-ffm",       // libsodium through Foreign Function & Memory (low overhead)
        "conscrypt-boringssl"         // BoringSSL through the JCA provider (native, the Envoy engine)
    );

    private Providers() { }

    public static Ed25519Provider get(String id) {
        return switch (id) {
            case "jca-sunec"                -> new JcaProvider();
            case "bc-lightweight"           -> new BcLightweightProvider();
            case "bc-jca"                   -> new BcJcaProvider();
            case "tink"                     -> new TinkProvider();
            case "libsodium-lazysodium-jna" -> new LazysodiumProvider();
            case "libsodium-panama-ffm"     -> new PanamaLibsodiumProvider();
            case "conscrypt-boringssl"      -> new ConscryptProvider();
            default -> throw new IllegalArgumentException("Unknown impl id: " + id);
        };
    }
}
