package com.openbanking.psu.auth.spi.mtls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Base64;

import org.junit.jupiter.api.Test;

/**
 * G9 — kiểm tính ROBUST của {@link XfccParser}: chống các né tránh STRIDE-Spoofing mà parser
 * naive (regex find / substring contains) mắc phải.
 */
class XfccParserTest {

  // hex SHA-256 mẫu (32 byte) — giả lập field Hash= của Envoy.
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
    // CN thật = customer-agent (trong Subject của leaf). Đúng.
    String ok = "Hash=" + HASH_HEX + ";Subject=\"CN=customer-agent,O=Bank\"";
    assertTrue(XfccParser.parse(ok).leafCnEquals("customer-agent"));

    // Né tránh naive: "CN=customer-agent" nằm trong By=URI/Subject của identity KHÁC, CN thật là evil.
    // Parser robust lấy CN từ Subject THẬT ⟹ KHÔNG khớp (substring contains sẽ khớp giả → nguy hiểm).
    String spoof = "By=spiffe://cluster/ns/CN=customer-agent;Subject=\"CN=evil-cluster\"";
    assertFalse(XfccParser.parse(spoof).leafCnEquals("customer-agent"));
    assertEquals("evil-cluster", XfccParser.parse(spoof).leafCommonName());
  }

  @Test
  void first_element_only_multi_hop() {
    // 2 hop: element ĐẦU (ingress tin cậy) Hash=A; element SAU (attacker) Hash=B.
    // Parser CHỈ lấy element đầu ⟹ không bị element sau ghi đè.
    String a = HASH_HEX;
    String b = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    String xfcc = "Hash=" + a + ";Subject=\"CN=customer-agent\","   // element[0] (đầu)
                + "Hash=" + b + ";Subject=\"CN=evil\"";             // element[1] (sau)
    String expectedA = Base64.getUrlEncoder().withoutPadding().encodeToString(hexToBytes(a));
    assertEquals(expectedA, XfccParser.parse(xfcc).leafThumbprintBase64Url());
    assertEquals("customer-agent", XfccParser.parse(xfcc).leafCommonName());
  }

  @Test
  void quoted_value_with_commas_does_not_split_element() {
    // Subject DN chứa dấu phẩy TRONG nháy kép ⟹ KHÔNG được hiểu là ranh giới element.
    // Parser robust giữ nguyên cả Subject (Hash vẫn lấy đúng từ CÙNG element) ⟹ CN trích đúng.
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
