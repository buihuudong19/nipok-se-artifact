import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

/**
 * Keygen ML-DSA-65 (FIPS 204) bằng JDK 24 built-in. In ra PRIV (PKCS8 b64url) + PUB (X.509 b64url)
 * để script e2e eval. Dùng: java MlDsaKeygen.java   (JDK 24+).
 */
public class MlDsaKeygen {
  public static void main(String[] a) throws Exception {
    KeyPair kp = KeyPairGenerator.getInstance("ML-DSA-65").generateKeyPair();
    var enc = Base64.getUrlEncoder().withoutPadding();
    System.out.println("PRIV=" + enc.encodeToString(kp.getPrivate().getEncoded()));   // PKCS8 ~4060B
    System.out.println("PUB=" + enc.encodeToString(kp.getPublic().getEncoded()));      // X.509 ~1974B
  }
}
