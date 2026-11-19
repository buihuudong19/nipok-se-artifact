package com.openbanking.psu.auth.spi.mtls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Base64;

import org.junit.jupiter.api.Test;

/**
 * Checks the ROBUSTNESS of {@link XfccParser} against the spoofing evasions (STRIDE) that naive
 * parsers (regex find / substring contains) are vulnerable to.
 */
class XfccParserTest {

  // sample hex SHA-256 (32 bytes) - simulates the Hash= field of Envoy.
  private static final String HASH_HEX =
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

  @Test
  void hash_field_preferred_and_converted_to_base64url() {
    String xfcc = "By=spiffe://x;Hash=" + HASH_HEX + ";Subject=\"CN=customer-agent\"";
    String expected = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(hexToBytes(HASH_HEX));
    assertEquals(expected, XfccParser.parse(xfcc).leafThumbprintBase64Url());
  }

  @Test
  void cn_from_subject_field_not_substring() {
    // real CN = customer-agent (in the Subject of the leaf). Correct.
    String ok = "Hash=" + HASH_HEX + ";Subject=\"CN=customer-agent,O=Bank\"";
    assertTrue(XfccParser.parse(ok).leafCnEquals("customer-agent"));

    // Naive evasion: "CN=customer-agent" appears in the By=URI/Subject of ANOTHER identity, the real CN is evil.
    // The robust parser takes the CN from the REAL Subject => NO match (a substring contains would match falsely -> dangerous).
    String spoof = "By=spiffe://cluster/ns/CN=customer-agent;Subject=\"CN=evil-cluster\"";
    assertFalse(XfccParser.parse(spoof).leafCnEquals("customer-agent"));
    assertEquals("evil-cluster", XfccParser.parse(spoof).leafCommonName());
  }

  @Test
  void first_element_only_multi_hop() {
    // 2 hops: FIRST element (trusted ingress) Hash=A; LATER element (attacker) Hash=B.
    // The parser takes ONLY the first element => the later element cannot override it.
    String a = HASH_HEX;
    String b = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    String xfcc = "Hash=" + a + ";Subject=\"CN=customer-agent\","   // element[0] (first)
                + "Hash=" + b + ";Subject=\"CN=evil\"";             // element[1] (sau)
    String expectedA = Base64.getUrlEncoder().withoutPadding().encodeToString(hexToBytes(a));
    assertEquals(expectedA, XfccParser.parse(xfcc).leafThumbprintBase64Url());
    assertEquals("customer-agent", XfccParser.parse(xfcc).leafCommonName());
  }

  @Test
  void quoted_value_with_commas_does_not_split_element() {
    // Subject DN with a comma INSIDE double quotes => must NOT be taken as an element boundary.
    // The robust parser keeps the whole Subject (Hash still taken from the SAME element) => the CN is extracted correctly.
    String xfcc = "Hash=" + HASH_HEX + ";Subject=\"CN=customer-agent,O=Acme, Inc.,C=VN\"";
    assertTrue(XfccParser.parse(xfcc).leafCnEquals("customer-agent"));
    String expected = Base64.getUrlEncoder().withoutPadding().encodeToString(hexToBytes(HASH_HEX));
    assertEquals(expected, XfccParser.parse(xfcc).leafThumbprintBase64Url());
  }

  @Test
  void empty_or_null_header_is_safe() {
    assertTrue(XfccParser.parse(null).isEmpty());
    assertTrue(XfccParser.parse("").isEmpty());
    assertNull(XfccParser.parse(null).leafThumbprintBase64Url());
    assertFalse(XfccParser.parse("").leafCnEquals("customer-agent"));
  }

  private static byte[] hexToBytes(String h) {
    byte[] out = new byte[h.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
    }
    return out;
  }
}
