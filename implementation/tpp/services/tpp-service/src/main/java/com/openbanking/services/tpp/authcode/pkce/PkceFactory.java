package com.openbanking.services.tpp.authcode.pkce;

/**
 * Chiến lược (Strategy) sinh PKCE. Tách interface để: (a) test bằng impl giả lập (verifier cố định),
 * (b) mở rộng (vd "plain") mà không sửa nơi dùng. RFC 7636 §4.2 khuyến nghị "S256".
 */
public interface PkceFactory {

  /** Sinh một cặp PKCE mới (verifier ngẫu nhiên + challenge tương ứng). */
  Pkce create();
}
