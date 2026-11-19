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
 * JMH PSU-mTLS (RFC 8410) - purely CPU-bound, the DIRECT COUNTERPART of {@code NipokBenchmark.verify_server}
 * (1 double-scalar multiplication) and the Argon2id verification. Measures the cryptographic cost of <b>one mTLS authentication event</b>
 * at the application layer - EXACTLY the BoringSSL operation run in Envoy in production (see docs/PSU-MTLS.md §3,
 * "layer disclosure": JMH-Java is a same-layer primitive proxy; the real deployment cost is measured with e2e/k6).
 *
 * <p>Two operations are separated for "fairness":
 * <ul>
 *   <li>{@link #parse_and_verify}: FROM THE RAW HEADER STRING (XFCC) -> parse the certificate -> verify. Comparable with
 *       "Argon2id verification from the password string" / "NIPoK verification from the proof bytes".</li>
 *   <li>{@link #verify_only}: certificate already parsed -> crypto ONLY (1× Ed25519 verification of the CA signature + binding).
 *       Isolates the crypto cost from the in-memory parse/decode.</li>
 * </ul>
 *
 * <p>{@code @Param sigProvider} names the verification engine (JCA SunEC pure Java vs Conscrypt/BoringSSL),
 * aligned with {@code NipokBenchmark.shaProvider}. {@code @Setup} absorbs keygen/certificate building/allocation -> OUTSIDE the measured loop.
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

  // default=SunEC(JCA pure-Java) | Conscrypt=BoringSSL(native) | elisabeth=SAME backend as NIPoK (fairness).
  @Param({"default", "Conscrypt", "elisabeth"})
  public String sigProvider;

  private MtlsCredentialVerifier verifier;
  private Ed25519CertCredential storedCred;
  private X509Certificate leaf;
  private X509Certificate[] chain;
  private CertPresentation presentation;
  private String rawXfccHeader;            // raw XFCC header (Cert= PEM percent-encoded) as sent by Envoy
  // sign_client (PoP in the TLS handshake = CertificateVerify): Ed25519 signature over the transcript hash, matching backend.
  private PrivateKey psuPriv;
  private byte[] psuSeed;
  private com.openbanking.psu.auth.spi.crypto.ed25519.ElisabethEd25519Signer elisabethSigner;
  private byte[] transcript;               // ~64B = TLS 1.3 transcript hash (SHA-512) signed in CertificateVerify
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

    // 1) Ed25519 CA (bank PSU CA) + 2) Ed25519 leaf (PSU) - keygen OUTSIDE the measured loop.
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
    KeyPair ca = kpg.generateKeyPair();
    KeyPair psu = kpg.generateKeyPair();

    X500Principal caDn = new X500Principal("CN=Bank PSU CA,O=OpenBanking");
    X500Principal leafDn = new X500Principal("CN=psu-0001,O=OpenBanking PSU");
    leaf = issueEd25519Cert(caDn, leafDn, psu, ca, provider);
    chain = new X509Certificate[] { leaf };

    // 3) Verifier with trust anchor = CA (a self-signed CA certificate is built to provide the anchor public key).
    X509Certificate caCert = issueEd25519Cert(caDn, caDn, ca, ca, provider);
    verifier = new MtlsCredentialVerifier(List.of(caCert), provider);

    // 4) Stored credential = raw public key + thumbprint (INDEPENDENT path from the leaf, as in the database).
    byte[] rawKey = Ed25519Certificates.rawPublicKey(leaf);
    storedCred = new Ed25519CertCredential(rawKey, Ed25519Certificates.thumbprintS256(leaf));
    presentation = new CertPresentation(leaf, chain);

    // 5) Raw XFCC header as set by Envoy: Cert="<PEM with %0A>".
    String pem = "-----BEGIN CERTIFICATE-----\n"
        + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(leaf.getEncoded())
        + "\n-----END CERTIFICATE-----\n";
    rawXfccHeader = "Cert=\"" + pem.replace("\n", "%0A") + "\"";

    // sign_client state: the PSU proof of possession in the handshake = Ed25519 signature over the transcript hash (CertificateVerify).
    provForSign = provider;
    psuPriv = psu.getPrivate();
    byte[] pk8 = psuPriv.getEncoded();
    psuSeed = java.util.Arrays.copyOfRange(pk8, pk8.length - 32, pk8.length);
    elisabethSigner = "elisabeth".equals(sigProvider)
        ? new com.openbanking.psu.auth.spi.crypto.ed25519.ElisabethEd25519Signer(null) : null;
    transcript = new byte[64];
    new SecureRandom().nextBytes(transcript);

    // Self-check: the verification must pass before measuring (otherwise JMH reports an error for this case).
    if (!verifier.verify(storedCred, presentation, null).ok()) {
      throw new RuntimeException("self-verify failed (sigProvider=" + sigProvider + ")");
    }
    X509Certificate parsed = XfccParser.parse(rawXfccHeader).leaf();
    if (parsed == null) {
      throw new RuntimeException("XfccParser cannot parse Cert= from the prepared header");
    }
  }

  /** FROM THE RAW HEADER STRING: parse XFCC -> certificate -> verify (counterpart of password/NIPoK from raw input). */
  @Benchmark
  @Threads(1)
  public boolean parse_and_verify() {
    X509Certificate parsedLeaf = XfccParser.parse(rawXfccHeader).leaf();
    return verifier.verify(storedCred, new CertPresentation(parsedLeaf, new X509Certificate[] { parsedLeaf }), null).ok();
  }

  /** Crypto ONLY: parsed certificate -> verification of the CA signature + binding (isolated from parsing). */
  @Benchmark
  @Threads(1)
  public boolean verify_only() {
    return verifier.verify(storedCred, presentation, null).ok();
  }

  /**
   * CLIENT: proof of possession of the PSU key in the TLS handshake = Ed25519 signature over the transcript hash (TLS 1.3
   * CertificateVerify analogue). Symmetric to {@code NipokBenchmark.prove_client}. The backend matches
   * sigProvider (elisabeth = the same library as NIPoK). Once per handshake (amortised with connection reuse).
   */
  @Benchmark
  @Threads(1)
  public byte[] sign_client() throws Exception {
    if (elisabethSigner != null) {
      return elisabethSigner.sign(psuSeed, transcript);            // elisabeth (same as NIPoK)
    }
    Signature s = (provForSign == null)
        ? Signature.getInstance("Ed25519") : Signature.getInstance("Ed25519", provForSign);
    s.initSign(psuPriv);
    s.update(transcript);
    return s.sign();
  }

  // ------------------------------- helpers building Ed25519 certificates (BC) -------------------------------

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
    // Signed with Ed25519 (RFC 8032). BC builds the ContentSigner; separate verification provider (SunEC/Conscrypt).
    JcaContentSignerBuilder csb = new JcaContentSignerBuilder("Ed25519").setProvider("BC");
    ContentSigner signer = csb.build(issuerKp.getPrivate());
    return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
  }
}
