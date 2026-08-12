package bench;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Cổng ĐÚNG-ĐẮN (chạy TRƯỚC benchmark): nạp CÙNG một khóa vào mọi impl khả dụng, ký bằng
 * từng impl rồi verify chéo bằng tất cả impl còn lại. EdDSA là deterministic → mọi chữ ký
 * phải BẰNG NHAU và verify chéo phải PASS (chứng minh tất cả tuân RFC 8032, liên thông).
 * Nếu fail → KHÔNG nên tin số liệu benchmark.
 *
 * Chạy:  java --enable-native-access=ALL-UNNAMED -cp <jmh-jar> bench.CorrectnessCheck
 */
public final class CorrectnessCheck {

    public static void main(String[] args) {
        byte[] msg = "open-banking-ed25519-interop-check".getBytes(StandardCharsets.UTF_8);

        // Khóa tham chiếu sinh từ impl baseline (jca-sunec)
        KeyPairRaw kp = Providers.get("jca-sunec").generateKeyPair();

        System.out.println("== Ed25519 cross-impl interop (cùng khóa) ==");
        List<Ed25519Provider> avail = new ArrayList<>();
        for (String id : Providers.IDS) {
            Ed25519Provider p = Providers.get(id);
            if (p.available()) {
                p.useKey(kp);
                avail.add(p);
                System.out.println("  [available] " + id);
            } else {
                System.out.println("  [SKIP — unavailable] " + id);
            }
        }

        byte[] reference = null;
        boolean allOk = true;
        for (Ed25519Provider signer : avail) {
            byte[] s = signer.sign(msg);
            if (reference == null) reference = s;
            else if (!java.util.Arrays.equals(reference, s)) {
                allOk = false;
                System.out.printf("  ✗ chữ ký của %s KHÁC tham chiếu (EdDSA phải deterministic!)%n", signer.id());
            }
            for (Ed25519Provider verifier : avail) {
                if (!verifier.verify(s, msg)) {
                    allOk = false;
                    System.out.printf("  ✗ sign=%s → verify=%s FAILED%n", signer.id(), verifier.id());
                }
            }
        }

        if (allOk) {
            System.out.println("  ✓ TẤT CẢ chữ ký bằng nhau & verify chéo PASS — liên thông OK, benchmark hợp lệ.");
        } else {
            System.out.println("  ✗ CÓ sai khác — sửa trước khi benchmark.");
            System.exit(1);
        }
    }
}
