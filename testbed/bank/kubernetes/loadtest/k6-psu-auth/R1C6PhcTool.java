/*
 * R1C6PhcTool.java - measurement helper used by run-all-psu.sh; NOT service code, does not run in the cluster.
 *
 * Serves the measured mechanism "password_owasp": same PASSWORD flow, same PSU pwd-1, same password and pepper, but during
 * the measurement the Argon2id PHC string of pwd-1 in the database is a PHC created at the OWASP floor (default m=19456 KiB,
 * t=2, p=1); afterwards the default auth-server parameters (m=65536, t=3, p=1) are restored. The auth-server verifies with the parameters stored IN the PHC
 * (Argon2idVerifier.verify), so the service does not have to be modified, rebuilt or redeployed.
 *
 * The PHC is created and checked with THE SAME class com.openbanking.psu.auth.spi.crypto.Argon2idVerifier (psu-auth-spi, Bouncy
 * Castle) contained in the JMH jar (crypto-jmh-*-jmh.jar). The verifier used for the checks is built like the auth-server one
 * (Argon2Params.financialDefault() + pepper). The pepper is decoded like DefaultSecurityConfig: Base64 of the trimmed string,
 * empty string = no pepper.
 *
 * Run (source-file mode, JDK >= 24 with javac):
 *   java -cp <JMH jar> R1C6PhcTool.java selftest [m t p]   self-test with a random pepper and password, no secret needed
 *   java -cp <JMH jar> R1C6PhcTool.java check              env R1C6_PEPPER_B64, R1C6_PW, R1C6_CHECK_PHC
 *   java -cp <JMH jar> R1C6PhcTool.java hash m t p         env R1C6_PEPPER_B64, R1C6_PW, R1C6_CHECK_PHC
 * hash: the PHC in R1C6_CHECK_PHC (the stored PHC) must verify with the given pepper and password, otherwise the tool stops
 * without creating anything. The new PHC must verify with the right password and be rejected with a wrong password before it
 * is printed (one single line on stdout).
 * The pepper and the password are accepted only through environment variables and are never printed.
 * Exit codes: 0 pass; 1 check failed; 2 wrong arguments or environment variables; 3 other error.
 */
import java.security.CodeSource;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.openbanking.psu.auth.spi.crypto.Argon2Params;
import com.openbanking.psu.auth.spi.crypto.Argon2idVerifier;
import com.openbanking.psu.auth.spi.model.PasswordHash;
import com.openbanking.psu.auth.spi.model.PasswordInput;
import com.openbanking.psu.auth.spi.model.VerificationResult;

public class R1C6PhcTool {

  static final Pattern PHC = Pattern.compile(
      "\\$argon2id\\$v=19\\$m=(\\d+),t=(\\d+),p=(\\d+)\\$([A-Za-z0-9+/]+)\\$([A-Za-z0-9+/]+)");
  static final int SALT_LEN = 16;   // as in Argon2Params.financialDefault()
  static final int HASH_LEN = 32;

  static final class Usage extends RuntimeException {
    Usage(String m) {
      super(m);
    }
  }

  public static void main(String[] args) {
    int rc;
    try {
      rc = run(args);
    } catch (Usage u) {
      System.err.println("R1C6PhcTool: " + u.getMessage());
      rc = 2;
    } catch (Throwable t) {
      // only the class name of the error is printed: the original message may contain input data
      System.err.println("R1C6PhcTool: error " + t.getClass().getName());
      rc = 3;
    }
    System.out.flush();
    System.exit(rc);
  }

  static int run(String[] a) {
    if (a.length == 0) {
      throw new Usage("missing command: selftest [m t p] | check | hash m t p");
    }
    switch (a[0]) {
      case "selftest":
        return selftest(a);
      case "check":
        return check();
      case "hash":
        return hash(a);
      default:
        throw new Usage("unknown command: " + a[0]);
    }
  }

  static int[] mtp(String[] a, int i) {
    if (a.length < i + 3) {
      throw new Usage("the 3 numbers m t p are required");
    }
    int m;
    int t;
    int p;
    try {
      m = Integer.parseInt(a[i]);
      t = Integer.parseInt(a[i + 1]);
      p = Integer.parseInt(a[i + 2]);
    } catch (NumberFormatException e) {
      throw new Usage("m t p must be integers");
    }
    if (p < 1 || p > 64 || t < 1 || t > 64 || m < 8 * p || m > (1 << 22)) {
      throw new Usage("m t p outside the allowed range");
    }
    return new int[] {m, t, p};
  }

  /** {m, t, p} of an Argon2id PHC in the format written by the auth-server; null if the format is wrong. */
  static int[] params(String phc) {
    if (phc == null) {
      return null;
    }
    Matcher x = PHC.matcher(phc);
    if (!x.matches()) {
      return null;
    }
    try {
      return new int[] {Integer.parseInt(x.group(1)), Integer.parseInt(x.group(2)), Integer.parseInt(x.group(3))};
    } catch (NumberFormatException e) {
      return null;
    }
  }

  static String env(String k, boolean required) {
    String v = System.getenv(k);
    if (required && (v == null || v.isEmpty())) {
      throw new Usage("missing environment variable " + k);
    }
    return v == null ? "" : v;
  }

  /** Pepper decoded exactly like DefaultSecurityConfig.passwordEncoder(): empty string = no pepper. */
  static byte[] pepper() {
    String b64 = env("R1C6_PEPPER_B64", false).trim();
    if (b64.isEmpty()) {
      return new byte[0];
    }
    try {
      return Base64.getDecoder().decode(b64);
    } catch (IllegalArgumentException e) {
      throw new Usage("R1C6_PEPPER_B64 is not Base64");
    }
  }

  static char[] pw() {
    return env("R1C6_PW", true).toCharArray();
  }

  /** Verifier built like the auth-server one: default parameters (used only for hashing) + pepper; verify reads the parameters from the PHC. */
  static Argon2idVerifier serverVerifier(byte[] pepper) {
    return new Argon2idVerifier(Argon2Params.financialDefault(), pepper);
  }

  static boolean verifies(Argon2idVerifier v, String phc, char[] pw) {
    return v.verify(new PasswordHash(phc), new PasswordInput(pw.clone()), null).ok();
  }

  static char[] wrong(char[] pw) {
    char[] w = Arrays.copyOf(pw, pw.length + 1);
    w[pw.length] = 'x';
    return w;
  }

  static String str(int[] c) {
    return "m=" + c[0] + ",t=" + c[1] + ",p=" + c[2];
  }

  static int check() {
    byte[] pepper = pepper();
    char[] pw = pw();
    String phc = env("R1C6_CHECK_PHC", true).trim();
    int[] c = params(phc);
    if (c == null) {
      System.out.println("FAIL bad_format");
      return 1;
    }
    VerificationResult r = serverVerifier(pepper).verify(new PasswordHash(phc), new PasswordInput(pw.clone()), null);
    System.out.println((r.ok() ? "OK " : "FAIL " + r.reason() + " ") + str(c));
    return r.ok() ? 0 : 1;
  }

  static int hash(String[] a) {
    int[] c = mtp(a, 1);
    byte[] pepper = pepper();
    char[] pw = pw();
    String cur = env("R1C6_CHECK_PHC", true).trim();
    Argon2idVerifier srv = serverVerifier(pepper);
    if (params(cur) == null || !verifies(srv, cur, pw)) {
      System.err.println("R1C6PhcTool: the stored PHC does not verify with the given pepper and password - no new PHC created");
      return 1;
    }
    String phc = new Argon2idVerifier(new Argon2Params(c[0], c[1], c[2], SALT_LEN, HASH_LEN), pepper).hash(pw.clone());
    int[] g = params(phc);
    boolean ok = g != null && Arrays.equals(g, c) && verifies(srv, phc, pw) && !verifies(srv, phc, wrong(pw));
    if (!ok) {
      System.err.println("R1C6PhcTool: the new PHC failed the self-check - not printed");
      return 1;
    }
    System.out.println(phc);
    return 0;
  }

  /** Self-test with a random pepper and password, for the OWASP configuration (or the given m t p) and the default configuration. */
  static int selftest(String[] a) {
    int[] owasp = a.length > 1 ? mtp(a, 1) : new int[] {19456, 2, 1};
    int[] def = {65536, 3, 1};
    SecureRandom rng = new SecureRandom();
    byte[] pepper = new byte[32];
    rng.nextBytes(pepper);
    byte[] other = pepper.clone();
    other[0] ^= 1;
    char[] pw = ("R1C6-selftest-" + Long.toHexString(rng.nextLong())).toCharArray();
    Argon2idVerifier srv = serverVerifier(pepper);
    Argon2idVerifier srvOther = serverVerifier(other);
    StringBuilder sb = new StringBuilder();
    boolean all = true;
    for (int[] c : new int[][] {owasp, def}) {
      String phc = new Argon2idVerifier(new Argon2Params(c[0], c[1], c[2], SALT_LEN, HASH_LEN), pepper).hash(pw.clone());
      int[] g = params(phc);
      boolean fmt = g != null && Arrays.equals(g, c);
      boolean ok = verifies(srv, phc, pw);
      boolean rejPw = !verifies(srv, phc, wrong(pw));
      boolean rejPepper = !verifies(srvOther, phc, pw);
      all &= fmt && ok && rejPw && rejPepper;
      sb.append(" | ").append(str(c)).append(": phc-format=").append(fmt)
          .append(" verify-by-default-verifier=").append(ok)
          .append(" wrong-password-rejected=").append(rejPw)
          .append(" wrong-pepper-rejected=").append(rejPepper);
    }
    System.out.println((all ? "SELFTEST OK" : "SELFTEST FAIL") + " java=" + Runtime.version() + sb
        + " | Argon2idVerifier: " + where(Argon2idVerifier.class) + " | BC " + bcVersion());
    return all ? 0 : 1;
  }

  static String where(Class<?> k) {
    try {
      CodeSource cs = k.getProtectionDomain().getCodeSource();
      return cs == null || cs.getLocation() == null ? "?" : cs.getLocation().getPath();
    } catch (RuntimeException e) {
      return "?";
    }
  }

  static String bcVersion() {
    try {
      Object p = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider").getDeclaredConstructor().newInstance();
      return String.valueOf(p.getClass().getMethod("getVersionStr").invoke(p));
    } catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
      return "?";
    }
  }
}
