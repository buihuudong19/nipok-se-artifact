package bench;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;

import com.openbanking.psu.auth.spi.crypto.mtls.MtlsCredentialVerifier;
import com.openbanking.psu.auth.spi.model.CertPresentation;
import com.openbanking.psu.auth.spi.model.Ed25519CertCredential;
import com.openbanking.psu.auth.spi.mtls.Ed25519Certificates;
import com.openbanking.psu.auth.spi.mtls.XfccParser;

/**
 * JMH PSU-mTLS (RFC 8410) — CPU-bound thuần, ĐỐI TRỌNG TRỰC TIẾP với {@code NipokBenchmark.verify_server}
 * (1 double-scalar-mul) và Argon2id verify. Đo chi phí mật mã của <b>một sự kiện xác thực mTLS</b> ở
 * tầng Application — CHÍNH là phép BoringSSL chạy tại Envoy ở production (xem docs/PSU-MTLS.md §3,
 * "layer disclosure": JMH-Java là proxy primitive cùng tầng; chi phí triển khai thật đo ở e2e/k6).
 *
 * <p>Tách 2 phép theo yêu cầu "tính công bằng":
 * <ul>
 *   <li>{@link #parse_and_verify}: TỪ RAW HEADER STRING (XFCC) → parse cert → verify. So với
 *       "Argon2id verify từ password string" / "NIPoK verify từ proof bytes".</li>
 *   <li>{@link #verify_only}: cert đã parse sẵn → CHỈ crypto (1× Ed25519 verify chữ ký CA + binding).
 *       Cô lập chi phí crypto khỏi parse/decode I/O-in-memory.</li>
 * </ul>
 *
 * <p>{@code @Param sigProvider} công bố engine verify (JCA SunEC thuần Java vs Conscrypt/BoringSSL),
 * đồng bộ {@code NipokBenchmark.shaProvider}. {@code @Setup} nuốt keygen/dựng-cert/alloc → NGOÀI vòng đo.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 8, time = 1)
@Fork(value = 2, jvmArgsAppend = {
    "--enable-native-access=ALL-UNNAMED",
    "--sun-misc-unsafe-memory-access=allow"
})
@State(Scope.Benchmark)
public class MtlsCertBenchmark {

  // default=SunEC(JCA pure-Java) | Conscrypt=BoringSSL(native) | elisabeth=CÙNG backend NIPoK (công bằng).
  @Param({"default", "Conscrypt", "elisabeth"})
  public String sigProvider;

  private MtlsCredentialVerifier verifier;
  private Ed25519CertCredential storedCred;
  private X509Certificate leaf;
  private X509Certificate[] chain;
  private CertPresentation presentation;
  private String rawXfccHeader;            // header XFCC thô (Cert= PEM percent-encoded) như Envoy gửi
  // sign_client (PoP TLS handshake = CertificateVerify): ký Ed25519 trên transcript-hash, backend khớp.
  private PrivateKey psuPriv;
  private byte[] psuSeed;
  private com.openbanking.psu.auth.spi.crypto.ed25519.ElisabethEd25519Signer elisabethSigner;
  private byte[] transcript;               // ~64B = TLS1.3 transcript hash (SHA-512) ký ở CertificateVerify
  private String provForSign;

  @Setup(Level.Trial)
  public void setup() throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    String provider = "default".equals(sigProvider) ? null : sigProvider;
    if ("Conscrypt".equals(sigProvider) && Security.getProvider("Conscrypt") == null) {
      try {
        Security.addProvider(org.conscrypt.Conscrypt.newProvider());   // BoringSSL Ed25519 verify
      } catch (Throwable ignore) { /* fallback JCA */ }
    }

    // 1) CA Ed25519 (Bank PSU CA) + 2) leaf Ed25519 (PSU) — keygen NGOÀI vòng đo.
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
    KeyPair ca = kpg.generateKeyPair();
    KeyPair psu = kpg.generateKeyPair();

    X500Principal caDn = new X500Principal("CN=Bank PSU CA,O=OpenBanking");
    X500Principal leafDn = new X500Principal("CN=psu-0001,O=OpenBanking PSU");
    leaf = issueEd25519Cert(caDn, leafDn, psu, ca, provider);
    chain = new X509Certificate[] { leaf };

    // 3) Verifier với trust-anchor = CA (build CA cert tự-ký để cung cấp public key anchor).
    X509Certificate caCert = issueEd25519Cert(caDn, caDn, ca, ca, provider);
    verifier = new MtlsCredentialVerifier(List.of(caCert), provider);

    // 4) Credential lưu = raw pubkey + thumbprint (đường ĐỘC LẬP với leaf, như DB).
    byte[] rawKey = Ed25519Certificates.rawPublicKey(leaf);
    storedCred = new Ed25519CertCredential(rawKey, Ed25519Certificates.thumbprintS256(leaf));
    presentation = new CertPresentation(leaf, chain);

    // 5) Raw XFCC header như Envoy set: Cert="<PEM với %0A>".
    String pem = "-----BEGIN CERTIFICATE-----\n"
        + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(leaf.getEncoded())
        + "\n-----END CERTIFICATE-----\n";
    rawXfccHeader = "Cert=\"" + pem.replace("\n", "%0A") + "\"";

    // sign_client state: PoP của PSU ở handshake = ký Ed25519 trên transcript-hash (CertificateVerify).
    provForSign = provider;
    psuPriv = psu.getPrivate();
    byte[] pk8 = psuPriv.getEncoded();
    psuSeed = java.util.Arrays.copyOfRange(pk8, pk8.length - 32, pk8.length);
    elisabethSigner = "elisabeth".equals(sigProvider)
        ? new com.openbanking.psu.auth.spi.crypto.ed25519.ElisabethEd25519Signer(null) : null;
    transcript = new byte[64];
    new SecureRandom().nextBytes(transcript);

    // Self-check: đảm bảo verify pass trước khi đo (sai → JMH báo lỗi case này).
    if (!verifier.verify(storedCred, presentation, null).ok()) {
      throw new RuntimeException("self-verify thất bại (sigProvider=" + sigProvider + ")");
    }
    X509Certificate parsed = XfccParser.parse(rawXfccHeader).leaf();
    if (parsed == null) {
      throw new RuntimeException("XfccParser không parse được Cert= từ header dựng sẵn");
    }
  }

  /** TỪ RAW HEADER STRING: parse XFCC → cert → verify (đối trọng password/NIPoK from-raw). */
  @Benchmark
  @Threads(1)
  public boolean parse_and_verify() {
    X509Certificate parsedLeaf = XfccParser.parse(rawXfccHeader).leaf();
    return verifier.verify(storedCred, new CertPresentation(parsedLeaf, new X509Certificate[] { parsedLeaf }), null).ok();
  }

  /** CHỈ crypto: cert đã parse → verify chữ ký CA + binding (cô lập khỏi parse). */
  @Benchmark
  @Threads(1)
  public boolean verify_only() {
    return verifier.verify(storedCred, presentation, null).ok();
  }

  /**
   * CLIENT: bằng chứng sở hữu khóa PSU ở TLS handshake = ký Ed25519 trên transcript-hash (TLS 1.3
   * CertificateVerify analog). Đối xứng với {@code NipokBenchmark.prove_client}. Backend khớp
   * sigProvider (elisabeth = cùng thư viện NIPoK). 1 lần/handshake (amortized nếu reuse connection).
   */
  @Benchmark
  @Threads(1)
  public byte[] sign_client() throws Exception {
    if (elisabethSigner != null) {
      return elisabethSigner.sign(psuSeed, transcript);            // elisabeth (đồng nhất NIPoK)
    }
    Signature s = (provForSign == null)
        ? Signature.getInstance("Ed25519") : Signature.getInstance("Ed25519", provForSign);
    s.initSign(psuPriv);
    s.update(transcript);
    return s.sign();
  }

  // ─────────────────────────────── helper dựng cert Ed25519 (BC) ───────────────────────────────

  private static X509Certificate issueEd25519Cert(X500Principal issuer, X500Principal subject,
      KeyPair subjectKp, KeyPair issuerKp, String sigProvider) throws Exception {
    Instant now = Instant.now();
    X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
        issuer,
        BigInteger.valueOf(new SecureRandom().nextLong() & 0x7fffffffffffffffL),
        Date.from(now.minus(1, ChronoUnit.HOURS)),
        Date.from(now.plus(365, ChronoUnit.DAYS)),
        subject,
        subjectKp.getPublic());
    // Ký bằng Ed25519 (RFC 8032). BC build ContentSigner; provider verify riêng (SunEC/Conscrypt).
    JcaContentSignerBuilder csb = new JcaContentSignerBuilder("Ed25519").setProvider("BC");
    ContentSigner signer = csb.build(issuerKp.getPrivate());
    return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
  }
}
