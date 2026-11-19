package com.openbanking.psu.auth.spi.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Claims parsed from a compact JWT (header + payload). NO dependency on a JOSE/Jackson library -
 * keeps {@code psu-auth-spi} PURE and GC-friendly for JMH. A minimal but STRUCTURALLY correct parser
 * (object walker, NO substring search) => a value cannot pose as a key (no claim confusion).
 *
 * @param alg header.alg (only for LOGGING/check == "EdDSA"; NOT used to choose the verification engine)
 */
public record JwtClaims(String alg, String typ, String iss, String sub, String aud,
                        long iat, long nbf, long exp, String jti) {

  private static final Base64.Decoder B64URL = Base64.getUrlDecoder();

  /** Parses the 2 split base64url parts (header, payload). Throws {@link JwtException} if malformed. */
  public static JwtClaims parse(String headerB64, String payloadB64) {
    Map<String, Object> h = MiniJson.parseObject(decode(headerB64, "header"));
    Map<String, Object> p = MiniJson.parseObject(decode(payloadB64, "payload"));
    return new JwtClaims(
        str(h, "alg"), str(h, "typ"),
        str(p, "iss"), str(p, "sub"), str(p, "aud"),
        lng(p, "iat"), lng(p, "nbf"), lng(p, "exp"), str(p, "jti"));
  }

  private static String decode(String b64, String what) {
    try {
      return new String(B64URL.decode(b64), StandardCharsets.UTF_8);
    } catch (IllegalArgumentException e) {
      throw new JwtException("base64url " + what + " malformed");
    }
  }

  private static String str(Map<String, Object> m, String k) {
    Object v = m.get(k);
    return v instanceof String s ? s : null;
  }

  private static long lng(Map<String, Object> m, String k) {
    Object v = m.get(k);
    return v instanceof Long l ? l : Long.MIN_VALUE;   // missing numeric claim -> MIN => the time check fails
  }

  /** JWT parsing exception (unchecked, light for the hot path). */
  public static final class JwtException extends RuntimeException {
    public JwtException(String m) { super(m); }
  }

  // --------------------------- minimal JSON object parser ---------------------------
  // Enough for flat claims: string + integer (seconds). Nested objects/arrays -> skipped (null). Escapes \" \\ \/ \n...
  private static final class MiniJson {
    private final String s;
    private int i;

    private MiniJson(String s) { this.s = s; }

    static Map<String, Object> parseObject(String json) {
      MiniJson m = new MiniJson(json);
      Map<String, Object> out = m.object();
      return out;
    }

    private Map<String, Object> object() {
      Map<String, Object> m = new HashMap<>();
      ws(); expect('{'); ws();
      if (peek() == '}') { i++; return m; }
      while (true) {
        ws();
        String k = readString();
        ws(); expect(':');
        Object v = readValue();
        m.put(k, v);
        ws();
        char c = next();
        if (c == '}') break;
        if (c != ',') throw err("expected ',' or '}'");
      }
      return m;
    }

    private Object readValue() {
      ws();
      char c = peek();
      if (c == '"') return readString();
      if (c == '{') { skipBalanced('{', '}'); return null; }
      if (c == '[') { skipBalanced('[', ']'); return null; }
      if (c == 't') { i += 4; return Boolean.TRUE; }
      if (c == 'f') { i += 5; return Boolean.FALSE; }
      if (c == 'n') { i += 4; return null; }
      return readNumber();
    }

    private String readString() {
      expect('"');
      StringBuilder sb = new StringBuilder();
      while (i < s.length()) {
        char c = s.charAt(i++);
        if (c == '"') return sb.toString();
        if (c == '\\' && i < s.length()) {
          char e = s.charAt(i++);
          switch (e) {
            case '"' -> sb.append('"');
            case '\\' -> sb.append('\\');
            case '/' -> sb.append('/');
            case 'n' -> sb.append('\n');
            case 't' -> sb.append('\t');
            case 'r' -> sb.append('\r');
            case 'b' -> sb.append('\b');
            case 'f' -> sb.append('\f');
            case 'u' -> { sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; }
            default -> sb.append(e);
          }
        } else {
          sb.append(c);
        }
      }
      throw err("unterminated string");
    }

    private Long readNumber() {
      int start = i;
      while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
      String num = s.substring(start, i);
      try {
        // Time claims are integer seconds; a fractional part is cut off.
        int dot = num.indexOf('.');
        return Long.parseLong(dot < 0 ? num : num.substring(0, dot));
      } catch (NumberFormatException e) {
        return Long.MIN_VALUE;
      }
    }

    private void skipBalanced(char open, char close) {
      int depth = 0;
      while (i < s.length()) {
        char c = s.charAt(i++);
        if (c == '"') { readStringTail(); continue; }
        if (c == open) depth++;
        else if (c == close) { if (--depth == 0) return; }
      }
    }

    private void readStringTail() {           // opening '"' consumed; reads up to the closing '"' (honours escapes)
      while (i < s.length()) {
        char c = s.charAt(i++);
        if (c == '\\') { i++; continue; }
        if (c == '"') return;
      }
    }

    private void ws() { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; }
    private char peek() { return i < s.length() ? s.charAt(i) : '\0'; }
    private char next() { return i < s.length() ? s.charAt(i++) : '\0'; }
    private void expect(char c) { if (next() != c) throw err("mong '" + c + "'"); }
    private JwtException err(String m) { return new JwtException("JSON: " + m + " @" + i); }
  }
}
