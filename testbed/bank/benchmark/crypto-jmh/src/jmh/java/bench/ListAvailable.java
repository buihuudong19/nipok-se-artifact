package bench;

/**
 * Prints the comma-separated list of the implementation ids AVAILABLE on the current machine.
 * run-bench.sh uses it to benchmark only the available implementations -> JMH reports no error for an implementation
 * without its native library (e.g. conscrypt when the native library does not load).
 *
 * Run:  java --enable-native-access=ALL-UNNAMED -cp <jmh-jar> bench.ListAvailable
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
            } catch (Throwable ignore) { /* treated as not available */ }
        }
        System.out.print(sb);
    }
}
