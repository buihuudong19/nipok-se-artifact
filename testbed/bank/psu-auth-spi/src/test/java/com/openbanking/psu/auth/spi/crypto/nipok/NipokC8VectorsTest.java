package com.openbanking.psu.auth.spi.crypto.nipok;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import com.openbanking.psu.auth.spi.crypto.ec.Ed25519Group;
import com.openbanking.psu.auth.spi.crypto.ec.ElisabethEd25519Group;
import com.openbanking.psu.auth.spi.crypto.ec.PreparedPoint;
import com.openbanking.psu.auth.spi.model.NipokContext;
import com.openbanking.psu.auth.spi.model.NipokProof;
import com.openbanking.psu.auth.spi.wallet.SimulatorWalletProvider;
import com.openbanking.psu.auth.spi.wallet.SimulatorWalletProvider.CustodyMode;

/**
 * Conformance tests (Reviewer 1, Comment 8): runs every test vector v2 (src/test/resources/nipok-test-vectors-v2.json)
 * on the real psu-auth-spi code: creates proofs (RESIDENT and SEALED wallets), checks them in the order of the
 * auth-server stages (base64url decoding, 96-byte length, canonical s, then the equation, on both the plain path and the
 * PreparedPoint path used by the auth-server), and the registration key rule (NipokEncoding.isValidEnrollmentKey). The
 * elisabeth backend always runs; the libsodium backend runs only when libsodium.so is present (otherwise skipped).
 * Writes the result of every vector to build/c8/java-vectors-&lt;backend&gt;.json (directory changed with -Dc8.out=...).
 * Test only, the runtime code is unchanged. The JSON is read with the small parser at the end of this file, because
 * psu-auth-spi has no JSON library in testImplementation.
 */
class NipokC8VectorsTest {

  private static final String RESOURCE = "/nipok-test-vectors-v2.json";
  private static final byte[] TAG_KAPPA = "NIPoK-nonce-key-v1".getBytes(StandardCharsets.UTF_8);
  private static final byte[] TAG_V = "NIPoK-nonce-v1".getBytes(StandardCharsets.UTF_8);

  @Test
  void vectors_v2_elisabeth() throws IOException {
    Report r = run(new ElisabethEd25519Group(null), "elisabeth");
    if (r.bad > 0) {
      throw new AssertionError("elisabeth: " + r.bad + " vector(s) differ: " + r.badIds);
    }
    assertThat(r.total > 0).isTrue();
  }

  @Test
  void vectors_v2_libsodium_if_available() throws IOException {
    Ed25519Group lib = libsodiumOrNull();
    Assumptions.assumeTrue(lib != null, "libsodium.so not present on this host: libsodium backend skipped");
    Report r = run(lib, "libsodium");
    if (r.bad > 0) {
      throw new AssertionError("libsodium: " + r.bad + " vector(s) differ: " + r.badIds);
    }
  }

  // ---------------------------------------------------------------------------------------------------------------

  private static Ed25519Group libsodiumOrNull() {
    try {
      Class<?> c = Class.forName("com.openbanking.psu.auth.spi.crypto.ec.LibsodiumEd25519Group");
      Object g = c.getConstructor(String.class).newInstance((String) null);
      Object ok = c.getMethod("available").invoke(g);
      return Boolean.TRUE.equals(ok) ? (Ed25519Group) g : null;
    } catch (ReflectiveOperationException | LinkageError e) {
      return null;
    }
  }

  private static final class Report {
    int total;
    int bad;
    final List<String> badIds = new ArrayList<>();
    final List<Map<String, Object>> rows = new ArrayList<>();

    void add(Map<String, Object> row) {
      total++;
      if (!Boolean.TRUE.equals(row.get("match"))) {
        bad++;
        badIds.add(String.valueOf(row.get("id")));
      }
      rows.add(row);
    }
  }

  @SuppressWarnings("unchecked")
  private Report run(Ed25519Group ec, String backend) throws IOException {
    Map<String, Object> d = (Map<String, Object>) MiniJson.parse(resourceText());
    NipokEngine engine = new NipokEngine(ec);
    Report rep = new Report();
    Map<String, Map<String, Object>> byId = new LinkedHashMap<>();

    for (Object o : (List<Object>) d.get("valid")) {
      Map<String, Object> t = (Map<String, Object>) o;
      byId.put(str(t, "id"), t);
      rep.add(checkValid(t, ec, engine));
    }
    for (Object o : (List<Object>) d.get("invalid")) {
      Map<String, Object> t = (Map<String, Object>) o;
      rep.add(checkInvalid(t, byId.get(str(t, "base")), engine, backend));
    }
    for (Object o : (List<Object>) d.get("enrollment_keys")) {
      Map<String, Object> t = (Map<String, Object>) o;
      rep.add(checkKey(t, ec, backend));
    }
    write(rep, backend, String.valueOf(d.get("name")));
    return rep;
  }

  private Map<String, Object> checkValid(Map<String, Object> t, Ed25519Group ec, NipokEngine engine) {
    byte[] x = hx(str(t, "x"));
    byte[] pub = hx(str(t, "X"));
    byte[] n = hx(str(t, "N"));
    byte[] cb = hx(str(t, "cb"));
    String idP = idString(t, "id_P");
    String idV = idString(t, "id_V");
    NipokContext c = new NipokContext(pub, idP, n, cb.length == 0 ? null : cb, idV);
    Map<String, Object> checks = new LinkedHashMap<>();
    SimulatorWalletProvider resident = new SimulatorWalletProvider(x.clone(), ec, engine);
    SimulatorWalletProvider sealed = new SimulatorWalletProvider(x.clone(), CustodyMode.SEALED, ec, engine);
    try {
      NipokProof p = resident.prove(c);
      NipokProof q = sealed.prove(c);
      byte[] kappa = ec.hashToScalar(TAG_KAPPA, x);
      byte[] v = ec.hashToScalar(TAG_V, kappa, pub, idP.getBytes(StandardCharsets.UTF_8), n, cb,
          idV.getBytes(StandardCharsets.UTF_8));
      checks.put("id_utf8", idBytesConsistent(t));
      checks.put("X", Arrays.equals(resident.publicPoint(), pub) && Arrays.equals(sealed.publicPoint(), pub));
      checks.put("kappa_v", Arrays.equals(kappa, hx(str(t, "kappa_v"))));
      checks.put("v", Arrays.equals(v, hx(str(t, "v"))));
      checks.put("V", Arrays.equals(p.commitment(), hx(str(t, "V"))) && Arrays.equals(ec.scalarMultBase(v), hx(str(t, "V"))));
      checks.put("e", Arrays.equals(engine.challenge(p.commitment(), c), hx(str(t, "e"))));
      checks.put("s", Arrays.equals(p.response(), hx(str(t, "s"))));
      checks.put("sealed_equals_resident", Arrays.equals(p.commitment(), q.commitment())
          && Arrays.equals(p.response(), q.response()));
      checks.put("blob", Base64.getUrlEncoder().withoutPadding()
          .encodeToString(concat(n, p.commitment(), p.response())).equals(str(t, "blob")));
      Outcome plain = decodeAndVerify(str(t, "blob"), pub, idP, cb, idV, engine, false);
      Outcome prep = decodeAndVerify(str(t, "blob"), pub, idP, cb, idV, engine, true);
      checks.put("verify_plain", plain.accepted);
      checks.put("verify_prepared", prep.accepted);
    } finally {
      sealed.close();
      resident.close();
    }
    boolean all = checks.values().stream().allMatch(Boolean.TRUE::equals);
    return row(t, "accept", all ? "accept" : "check-failed", null, all, checks);
  }

  private Map<String, Object> checkInvalid(Map<String, Object> t, Map<String, Object> base, NipokEngine engine,
                                           String backend) {
    Map<String, Object> ctx = new LinkedHashMap<>();
    for (String k : new String[] {"X", "cb", "id_V"}) {
      Object val = t.containsKey(k) ? t.get(k) : (base != null ? base.get(k) : null);
      if (val != null) {
        ctx.put(k, val);
      }
    }
    // id_P and id_P_utf8 come from the same source: the vector if it has id_P, otherwise the original vector (v1 records only the blob)
    Map<String, Object> idSrc = t.containsKey("id_P") ? t : base;
    if (idSrc != null) {
      ctx.put("id_P", idSrc.get("id_P"));
      if (idSrc.containsKey("id_P_utf8")) {
        ctx.put("id_P_utf8", idSrc.get("id_P_utf8"));
      }
    }
    byte[] pub = hx(str(ctx, "X"));
    byte[] cb = hx(str(ctx, "cb"));
    String idP = idString(ctx, "id_P");
    String idV = idString(ctx, "id_V");
    Map<String, Object> detail = new LinkedHashMap<>();
    Outcome plain;
    Outcome prep;
    if (t.containsKey("blob")) {
      plain = decodeAndVerify(str(t, "blob"), pub, idP, cb, idV, engine, false);
      prep = decodeAndVerify(str(t, "blob"), pub, idP, cb, idV, engine, true);
    } else {
      plain = verifyFields(pub, hx(str(t, "V")), hx(str(t, "s")), hx(str(t, "N")), idP, cb, idV, engine, false);
      prep = verifyFields(pub, hx(str(t, "V")), hx(str(t, "s")), hx(str(t, "N")), idP, cb, idV, engine, true);
    }
    String want = (String) t.get("stage");
    boolean match = !plain.accepted && !prep.accepted && equalsOrNull(want, plain.stage) && equalsOrNull(want, prep.stage);
    if (t.containsKey("V") && t.containsKey("s") && t.containsKey("N") && t.containsKey("equation_alone")) {
      NipokContext c = new NipokContext(pub, idP, hx(str(t, "N")), cb.length == 0 ? null : cb, idV);
      boolean eq = engine.verify(pub, new NipokProof(hx(str(t, "V")), hx(str(t, "s"))), c);
      String expect = "libsodium".equals(backend) && t.containsKey("equation_alone_libsodium")
          ? str(t, "equation_alone_libsodium") : str(t, "equation_alone");
      detail.put("equation_alone", eq ? "holds" : "fails");
      match = match && (eq ? "holds" : "fails").equals(expect);
    }
    if (ctx.containsKey("id_P_utf8")) {
      detail.put("id_utf8", idBytesConsistent(ctx));
      match = match && idBytesConsistent(ctx);
    }
    detail.put("stage_prepared", prep.stage);
    return row(t, "reject", plain.accepted ? "accept" : "reject", plain.stage, match, detail);
  }

  private Map<String, Object> checkKey(Map<String, Object> t, Ed25519Group ec, String backend) {
    byte[] key = hx(str(t, "X"));
    boolean rule = NipokEncoding.isValidEnrollmentKey(key);
    Map<String, Object> detail = new LinkedHashMap<>();
    boolean match = (rule ? "accept" : "reject").equals(str(t, "expected"));
    if ("libsodium".equals(backend)) {
      boolean lib;
      try {
        lib = key.length == 32 && ec.isValidPublicPoint(key);
      } catch (RuntimeException e) {
        lib = false;
      }
      detail.put("libsodium_is_valid_point", lib);
      match = match && (lib ? "accept" : "reject").equals(str(t, "expected"));
    }
    Map<String, Object> r = row(t, str(t, "expected"), rule ? "accept" : "reject", rule ? null : "registration", match,
        detail);
    r.put("category", "key_registration");
    return r;
  }

  // ---- the rules of the authorization server (NipokAuthenticationProvider), in its order -----------------------

  private record Outcome(boolean accepted, String stage) { }

  private static Outcome decodeAndVerify(String blob, byte[] pub, String idP, byte[] cb, String idV,
                                         NipokEngine engine, boolean prepared) {
    byte[] raw;
    try {
      raw = Base64.getUrlDecoder().decode(blob);
    } catch (IllegalArgumentException e) {
      return new Outcome(false, "decode_encoding");
    }
    if (raw.length != 96) {
      return new Outcome(false, "decode_length");
    }
    return verifyFields(pub, Arrays.copyOfRange(raw, 32, 64), Arrays.copyOfRange(raw, 64, 96),
        Arrays.copyOfRange(raw, 0, 32), idP, cb, idV, engine, prepared);
  }

  private static Outcome verifyFields(byte[] pub, byte[] v, byte[] s, byte[] n, String idP, byte[] cb, String idV,
                                      NipokEngine engine, boolean prepared) {
    if (!NipokEncoding.isCanonicalScalar(s)) {
      return new Outcome(false, "noncanonical_s");
    }
    NipokContext c = new NipokContext(pub, idP, n, cb.length == 0 ? null : cb, idV);
    NipokProof proof = new NipokProof(v, s);
    boolean ok;
    if (prepared) {
      PreparedPoint pp = engine.prepare(pub);
      ok = engine.verify(pp, proof, c);
    } else {
      ok = engine.verify(pub, proof, c);
    }
    return ok ? new Outcome(true, null) : new Outcome(false, "equation");
  }

  // ---- helpers -----------------------------------------------------------------------------------------------

  private static boolean equalsOrNull(String want, String got) {
    return want == null || want.equals(got);
  }

  private static String idString(Map<String, Object> t, String k) {
    Object hex = t.get(k + "_utf8");
    if (hex != null) {
      return new String(hx((String) hex), StandardCharsets.UTF_8);
    }
    return str(t, k);
  }

  private static boolean idBytesConsistent(Map<String, Object> t) {
    Object hex = t.get("id_P_utf8");
    return hex == null || Arrays.equals(str(t, "id_P").getBytes(StandardCharsets.UTF_8), hx((String) hex));
  }

  private static Map<String, Object> row(Map<String, Object> t, String expected, String result, String stage,
                                         boolean match, Map<String, Object> detail) {
    Map<String, Object> r = new LinkedHashMap<>();
    r.put("id", t.get("id"));
    r.put("category", t.get("category"));
    r.put("expected", expected);
    r.put("result", result);
    r.put("stage", stage);
    r.put("expected_stage", t.containsKey("stage") ? t.get("stage") : t.get("rule"));
    r.put("match", match);
    r.put("detail", detail);
    return r;
  }

  private static String str(Map<String, Object> t, String k) {
    Object v = t.get(k);
    if (!(v instanceof String s)) {
      throw new IllegalStateException("field " + k + " missing in " + t.get("id"));
    }
    return s;
  }

  private static byte[] hx(String h) {
    byte[] o = new byte[h.length() / 2];
    for (int i = 0; i < o.length; i++) {
      o[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
    }
    return o;
  }

  private static byte[] concat(byte[]... parts) {
    int n = 0;
    for (byte[] p : parts) {
      n += p.length;
    }
    byte[] o = new byte[n];
    int i = 0;
    for (byte[] p : parts) {
      System.arraycopy(p, 0, o, i, p.length);
      i += p.length;
    }
    return o;
  }

  private String resourceText() throws IOException {
    try (InputStream in = getClass().getResourceAsStream(RESOURCE)) {
      if (in == null) {
        throw new IOException("cannot find " + RESOURCE + " on the test classpath (src/test/resources)");
      }
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  private static void write(Report rep, String backend, String name) throws IOException {
    Path dir = Path.of(System.getProperty("c8.out", "build/c8"));
    Files.createDirectories(dir);
    Map<String, Object> top = new LinkedHashMap<>();
    top.put("tool", "NipokC8VectorsTest (R1C8-v1.1, JUnit on psu-auth-spi)");
    top.put("backend", backend);
    top.put("java", System.getProperty("java.version") + " " + System.getProperty("java.vm.name"));
    top.put("vectors_name", name);
    top.put("total", rep.total);
    top.put("matching", rep.total - rep.bad);
    top.put("mismatching", rep.bad);
    top.put("results", rep.rows);
    Files.writeString(dir.resolve("java-vectors-" + backend + ".json"), MiniJson.write(top) + "\n",
        StandardCharsets.UTF_8);
  }

  /** Minimal JSON reader/writer (object, array, string, number, true/false/null), enough for the test vector file. */
  static final class MiniJson {
    private final String s;
    private int i;

    private MiniJson(String s) {
      this.s = s;
    }

    static Object parse(String text) {
      MiniJson p = new MiniJson(text);
      Object v = p.value();
      p.ws();
      if (p.i != p.s.length()) {
        throw new IllegalArgumentException("JSON: trailing characters at position " + p.i);
      }
      return v;
    }

    private void ws() {
      while (i < s.length() && " \t\r\n".indexOf(s.charAt(i)) >= 0) {
        i++;
      }
    }

    private Object value() {
      ws();
      char c = s.charAt(i);
      switch (c) {
        case '{':
          return object();
        case '[':
          return array();
        case '"':
          return string();
        case 't':
          expect("true");
          return Boolean.TRUE;
        case 'f':
          expect("false");
          return Boolean.FALSE;
        case 'n':
          expect("null");
          return null;
        default:
          return number();
      }
    }

    private void expect(String w) {
      if (!s.startsWith(w, i)) {
        throw new IllegalArgumentException("JSON: expected " + w + " at position " + i);
      }
      i += w.length();
    }

    private Map<String, Object> object() {
      Map<String, Object> m = new LinkedHashMap<>();
      i++;
      ws();
      if (s.charAt(i) == '}') {
        i++;
        return m;
      }
      while (true) {
        ws();
        String k = string();
        ws();
        expect(":");
        m.put(k, value());
        ws();
        char c = s.charAt(i++);
        if (c == '}') {
          return m;
        }
        if (c != ',') {
          throw new IllegalArgumentException("JSON: expected , or } at position " + (i - 1));
        }
      }
    }

    private List<Object> array() {
      List<Object> a = new ArrayList<>();
      i++;
      ws();
      if (s.charAt(i) == ']') {
        i++;
        return a;
      }
      while (true) {
        a.add(value());
        ws();
        char c = s.charAt(i++);
        if (c == ']') {
          return a;
        }
        if (c != ',') {
          throw new IllegalArgumentException("JSON: expected , or ] at position " + (i - 1));
        }
      }
    }

    private String string() {
      if (s.charAt(i) != '"') {
        throw new IllegalArgumentException("JSON: expected a string at position " + i);
      }
      i++;
      StringBuilder b = new StringBuilder();
      while (true) {
        char c = s.charAt(i++);
        if (c == '"') {
          return b.toString();
        }
        if (c != '\\') {
          b.append(c);
          continue;
        }
        char e = s.charAt(i++);
        switch (e) {
          case '"', '\\', '/' -> b.append(e);
          case 'b' -> b.append('\b');
          case 'f' -> b.append('\f');
          case 'n' -> b.append('\n');
          case 'r' -> b.append('\r');
          case 't' -> b.append('\t');
          case 'u' -> {
            b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
            i += 4;
          }
          default -> throw new IllegalArgumentException("JSON: unknown escape \\" + e);
        }
      }
    }

    private Object number() {
      int j = i;
      while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) {
        i++;
      }
      String t = s.substring(j, i);
      if (t.isEmpty()) {
        throw new IllegalArgumentException("JSON: unexpected value at position " + j);
      }
      return t.contains(".") || t.contains("e") || t.contains("E") ? (Object) Double.valueOf(t) : (Object) Long.valueOf(t);
    }

    static String write(Object o) {
      StringBuilder b = new StringBuilder();
      emit(o, b);
      return b.toString();
    }

    @SuppressWarnings("unchecked")
    private static void emit(Object o, StringBuilder b) {
      if (o == null) {
        b.append("null");
      } else if (o instanceof String str) {
        b.append('"');
        for (char c : str.toCharArray()) {
          switch (c) {
            case '"' -> b.append("\\\"");
            case '\\' -> b.append("\\\\");
            case '\n' -> b.append("\\n");
            case '\r' -> b.append("\\r");
            case '\t' -> b.append("\\t");
            default -> {
              if (c < 0x20) {
                b.append(String.format("\\u%04x", (int) c));
              } else {
                b.append(c);
              }
            }
          }
        }
        b.append('"');
      } else if (o instanceof Map<?, ?> m) {
        b.append('{');
        boolean first = true;
        for (Map.Entry<?, ?> e : m.entrySet()) {
          if (!first) {
            b.append(',');
          }
          first = false;
          emit(String.valueOf(e.getKey()), b);
          b.append(':');
          emit(e.getValue(), b);
        }
        b.append('}');
      } else if (o instanceof List<?> l) {
        b.append('[');
        for (int k = 0; k < l.size(); k++) {
          if (k > 0) {
            b.append(',');
          }
          emit(l.get(k), b);
        }
        b.append(']');
      } else {
        b.append(o);
      }
    }
  }
}
