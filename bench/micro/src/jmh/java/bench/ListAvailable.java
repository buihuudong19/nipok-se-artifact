package bench;

/**
 * In ra danh sách id impl KHẢ DỤNG (phân tách bằng dấu phẩy) trên máy hiện tại.
 * run-bench.sh dùng để chỉ benchmark impl khả dụng → tránh JMH báo lỗi cho impl thiếu native
 * (vd conscrypt nếu native không load).
 *
 * Chạy:  java --enable-native-access=ALL-UNNAMED -cp <jmh-jar> bench.ListAvailable
 */
public final class ListAvailable {
    public static void main(String[] args) {
        StringBuilder sb = new StringBuilder();
        for (String id : Providers.IDS) {
            try {
                if (Providers.get(id).available()) {
                    if (sb.length() > 0) sb.append(',');
                    sb.append(id);
                }
            } catch (Throwable ignore) { /* coi như không khả dụng */ }
        }
        System.out.print(sb);
    }
}
