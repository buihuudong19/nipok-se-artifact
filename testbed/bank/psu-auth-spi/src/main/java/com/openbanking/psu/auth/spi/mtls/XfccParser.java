package com.openbanking.psu.auth.spi.mtls;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * ROBUST parser for the header {@code X-Forwarded-Client-Cert} (XFCC, Envoy/Istio).
 *
 * <p>Replaces naive parsers ({@code "Cert=\"([^\"]*)\""} + {@code find()}, or
 * {@code xfcc.contains("CN=...")}), which have 3 spoofing risks (STRIDE):
 * <ol>
 *   <li><b>Several elements (multi-hop):</b> XFCC is a comma-separated list at the top level,
 *       ONE element per proxy hop. {@code Pattern.find()} may capture the element of a LATER hop.
 *       This parser takes ONLY the <b>FIRST element</b> - set by the trusted ingress (SANITIZE_SET).</li>
 *   <li><b>Quoted/escaped values:</b> {@code Subject="CN=x,O=\"y\""} contains {@code , ; "} -
 *       a raw split breaks. This tokenizer honours double quotes and the escapes {@code \" \\}.</li>
 *   <li><b>Fake CN substring:</b> {@code contains("CN=customer-agent")} also matches when the string appears
 *       in the By=URI/Subject of ANOTHER certificate. The parser takes the CN from the <b>real Subject of the leaf certificate</b>.</li>
 * </ol>
 *
 * <p>Grammar (Envoy): {@code header = element *("," element)}; {@code element = kv *(";" kv)};
 * {@code kv = key "=" value}; value = token | quoted-string. Keys (case-insensitive):
 * By, Hash, Cert, Chain, Subject, URI, DNS. Cert/Chain = PEM percent-encoded; Hash = hex SHA-256(DER).
 *
 * <p>Pure Java (no Spring dependency) => shared by the auth-server and the (reactive) aggregators.
 */
public final class XfccParser {

  public static final String HEADER = "X-Forwarded-Client-Cert";

  /** KV of the FIRST element (keys lower-cased). */
  private final Map<String, String> kv;

  private XfccParser(Map<String, String> kv) {
    this.kv = kv;
  }

  /** Parses the first element (the most trusted). Null/empty header -> empty parser. */
  public static XfccParser parse(String header) {
    if (header == null || header.isBlank()) {
      return new XfccParser(Map.of());
    }
    return new XfccParser(parseFirstElement(header));
  }

  public boolean isEmpty() {
    return kv.isEmpty();
  }

  /** Field value (case-insensitive key); null if absent. */
  public String get(String key) {
    return kv.get(key.toLowerCase());
  }

  /** Leaf certificate (field {@code Cert=}); null if missing/unparseable. */
  public X509Certificate leaf() {
    return firstCert(get("cert"));
  }

  /** Full chain (field {@code Chain=}); empty if missing. */
  public X509Certificate[] chain() {
    String pem = get("chain");
    if (pem == null || pem.isEmpty()) {
      X509Certificate l = leaf();
      return l != null ? new X509Certificate[] { l } : new X509Certificate[0];
    }
    try {
      return CertificateFactory.getInstance("X.509")
          .generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)))
          .stream().map(X509Certificate.class::cast).toArray(X509Certificate[]::new);
    } catch (Exception e) {
      return new X509Certificate[0];
    }
  }

  /**
   * SHA-256 thumbprint (base64url, no padding) of the leaf certificate - for RFC 8705 {@code cnf.x5t#S256}.
   * PREFERS the field {@code Hash=} (hex SHA-256(DER) computed by Envoy) => NO PEM parsing needed;
   * falls back to computing it from {@code Cert=}. null if both are missing.
   */
  public String leafThumbprintBase64Url() {
    String hashHex = get("hash");
    if (hashHex != null && !hashHex.isEmpty()) {
      byte[] der = hexToBytes(hashHex);
      if (der != null && der.length == 32) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(der);
      }
    }
    X509Certificate leaf = leaf();
    if (leaf == null) {
      return null;
    }
    try {
      byte[] hash = MessageDigest.getInstance("SHA-256").digest(leaf.getEncoded());
      return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    } catch (Exception e) {
      return null;
    }
  }

  /** CN in the Subject of the leaf certificate (from the certificate itself, NOT a header substring). null if absent. */
  public String leafCommonName() {
    X509Certificate leaf = leaf();
    if (leaf != null) {
      String cn = commonNameOf(leaf.getSubjectX500Principal().getName());
      if (cn != null) {
        return cn;
      }
    }
    // Fallback: field Subject= (DN) when there is no Cert= (Envoy may forward only Subject/Hash).
    return commonNameOf(get("subject"));
  }

  /** True if the leaf certificate has exactly the expected CN (compares the CN value, NOT a substring of the whole header). */
  public boolean leafCnEquals(String expectedCn) {
    String cn = leafCommonName();
    return cn != null && cn.equals(expectedCn);
  }

  // ------------------------------- internal -------------------------------

  /** Splits the KV of the FIRST element (stops at a top-level comma; honours double quotes and escapes). */
  private static Map<String, String> parseFirstElement(String h) {
    List<String> kvs = new ArrayList<>();
    StringBuilder cur = new StringBuilder();
    boolean inQuote = false;
    for (int i = 0; i < h.length(); i++) {
      char c = h.charAt(i);
      if (inQuote) {
        if (c == '\\' && i + 1 < h.length()) {       // escape \" \\
          cur.append(c).append(h.charAt(++i));
          continue;
        }
        if (c == '"') {
          inQuote = false;
        }
        cur.append(c);
      } else if (c == '"') {
        inQuote = true;
        cur.append(c);
      } else if (c == ',') {                          // end of the FIRST element
        break;
      } else if (c == ';') {                          // KV boundary
        kvs.add(cur.toString());
        cur.setLength(0);
      } else {
        cur.append(c);
      }
    }
    if (cur.length() > 0) {
      kvs.add(cur.toString());
    }
    Map<String, String> map = new LinkedHashMap<>();
    for (String pair : kvs) {
      int eq = pair.indexOf('=');
      if (eq <= 0) {
        continue;
      }
      String key = pair.substring(0, eq).trim().toLowerCase();
      String val = pair.substring(eq + 1).trim();
      val = unquote(val);
      // Cert/Chain are percent-encoded PEM (space=%20, newline=%0A).
      if (key.equals("cert") || key.equals("chain")) {
        val = percentDecode(val);
      }
      map.put(key, val);
    }
    return map;
  }

  /** Removes surrounding double quotes and un-escapes {@code \" \\}. */
  private static String unquote(String v) {
    if (v.length() >= 2 && v.charAt(0) == '"' && v.charAt(v.length() - 1) == '"') {
      String inner = v.substring(1, v.length() - 1);
      StringBuilder sb = new StringBuilder(inner.length());
      for (int i = 0; i < inner.length(); i++) {
        char c = inner.charAt(i);
        if (c == '\\' && i + 1 < inner.length()) {
          sb.append(inner.charAt(++i));
        } else {
          sb.append(c);
        }
      }
      return sb.toString();
    }
    return v;
  }

  /**
   * Percent-decodes ONLY %XX (Istio encodes space=%20, newline=%0A). URLDecoder is NOT used because it
   * maps '+' to space, which corrupts the base64 of the certificate (base64 contains '+').
   */
  static String percentDecode(String s) {
    StringBuilder out = new StringBuilder(s.length());
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c == '%' && i + 2 < s.length()) {
        int hi = Character.digit(s.charAt(i + 1), 16);
        int lo = Character.digit(s.charAt(i + 2), 16);
        if (hi >= 0 && lo >= 0) {
          out.append((char) ((hi << 4) + lo));
          i += 2;
          continue;
        }
      }
      out.append(c);
    }
    return out.toString();
  }

  private static X509Certificate firstCert(String pem) {
    if (pem == null || pem.isEmpty()) {
      return null;
    }
    try {
      return (X509Certificate) CertificateFactory.getInstance("X.509")
          .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
    } catch (Exception e) {
      return null;
    }
  }

  /** Extracts CN= from a DN (RFC 2253), escape-safe. null if absent. */
  static String commonNameOf(String dn) {
    if (dn == null) {
      return null;
    }
    // RDN split honouring the escape '\,' - enough for DNs produced by X500Principal.getName().
    StringBuilder cur = new StringBuilder();
    List<String> rdns = new ArrayList<>();
    for (int i = 0; i < dn.length(); i++) {
      char c = dn.charAt(i);
      if (c == '\\' && i + 1 < dn.length()) {
        cur.append(c).append(dn.charAt(++i));
      } else if (c == ',') {
        rdns.add(cur.toString());
        cur.setLength(0);
      } else {
        cur.append(c);
      }
    }
    rdns.add(cur.toString());
    for (String rdn : rdns) {
      String t = rdn.trim();
      if (t.regionMatches(true, 0, "CN=", 0, 3)) {
        return t.substring(3).replace("\\,", ",").replace("\\\"", "\"").trim();
      }
    }
    return null;
  }

  private static byte[] hexToBytes(String hex) {
    String h = hex.trim();
    int n = h.length();
    if (n % 2 != 0) {
      return null;
    }
    byte[] out = new byte[n / 2];
    for (int i = 0; i < n; i += 2) {
      int hi = Character.digit(h.charAt(i), 16);
      int lo = Character.digit(h.charAt(i + 1), 16);
      if (hi < 0 || lo < 0) {
        return null;
      }
      out[i / 2] = (byte) ((hi << 4) + lo);
    }
    return out;
  }
}
