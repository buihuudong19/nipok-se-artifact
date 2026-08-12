package bench;

import bench.impl.*;
import java.util.List;

/** Registry — ánh xạ id → impl. Thêm/bớt giải pháp ở đây. */
public final class Providers {

    /** Thứ tự hiển thị; cũng là tập @Param mặc định của benchmark. */
    public static final List<String> IDS = List.of(
        "jca-sunec",                  // baseline: JDK built-in (SunEC, pure-Java)
        "bc-lightweight",             // BouncyCastle API nhẹ (nhanh nhất của BC)
        "bc-jca",                     // BouncyCastle qua JCA provider (có overhead khung)
        "tink",                       // Google Tink (subtle Ed25519, pure-Java)
        "libsodium-lazysodium-jna",   // libsodium qua JNA (overhead FFI cao)
        "libsodium-panama-ffm",       // libsodium qua Foreign Function & Memory (overhead thấp)
        "conscrypt-boringssl"         // BoringSSL qua JCA provider (native, đúng engine Envoy)
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
