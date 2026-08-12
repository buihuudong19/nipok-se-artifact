package com.openbanking.services.tpp.mtls;

import java.io.ByteArrayInputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECParameterSpec;
import java.util.Base64;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.openbanking.services.tpp.config.TppProperties;
import com.openbanking.services.tpp.vault.VaultClient;

/**
 * Cấp cert cho khóa nằm trong Vault Transit (key custody): dựng CSR với PUBLIC key của Transit,
 * ký CSR bằng chính Vault Transit (proof-of-possession), rồi nhờ Vault PKI ký → cert.
 * Private key KHÔNG bao giờ rời Vault.
 */
@Component
public class CertIssuer {

  private static final Logger LOG = LoggerFactory.getLogger(CertIssuer.class);

  private final VaultClient vault;
  private final TppProperties props;

  public CertIssuer(VaultClient vault, TppProperties props) {
    this.vault = vault;
    this.props = props;
  }

  /** Kết quả: chuỗi cert (leaf→CA) + tham số đường cong (cho VaultPrivateKey). */
  public record Material(X509Certificate[] chain, ECParameterSpec ecParams) {}

  public Material issue() throws Exception {
    PublicKey pub = parsePublicKey(vault.transitPublicKeyPem());
    ECParameterSpec ecParams = ((java.security.interfaces.ECPublicKey) pub).getParams();

    // CSR ký bằng Vault Transit (signer ngoài)
    ContentSigner signer = new ContentSigner() {
      private final java.io.ByteArrayOutputStream tbs = new java.io.ByteArrayOutputStream();
      @Override public org.bouncycastle.asn1.x509.AlgorithmIdentifier getAlgorithmIdentifier() {
        return new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WITHECDSA");
      }
      @Override public OutputStream getOutputStream() { return tbs; }
      @Override public byte[] getSignature() { return vault.transitSign(tbs.toByteArray()); }
    };
    PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(
        new X500Name(props.client().subjectDn()), pub).build(signer);

    String certPem = vault.pkiSignCsr(toPem("CERTIFICATE REQUEST", csr.getEncoded()));
    X509Certificate leaf = parseCert(certPem);
    X509Certificate ca = parseCert(vault.pkiCaPem());
    LOG.info("Cert cấp cho Transit key: subject={}", leaf.getSubjectX500Principal());
    return new Material(new X509Certificate[] {leaf, ca}, ecParams);
  }

  private static PublicKey parsePublicKey(String pem) throws Exception {
    String b64 = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
    var spec = new java.security.spec.X509EncodedKeySpec(Base64.getDecoder().decode(b64));
    return java.security.KeyFactory.getInstance("EC").generatePublic(spec);
  }

  private static X509Certificate parseCert(String pem) throws Exception {
    return (X509Certificate) CertificateFactory.getInstance("X.509")
        .generateCertificate(new ByteArrayInputStream(pem.getBytes()));
  }

  private static String toPem(String type, byte[] der) throws Exception {
    StringWriter sw = new StringWriter();
    try (PemWriter pw = new PemWriter(sw)) {
      pw.writeObject(new PemObject(type, der));
    }
    return sw.toString();
  }
}
