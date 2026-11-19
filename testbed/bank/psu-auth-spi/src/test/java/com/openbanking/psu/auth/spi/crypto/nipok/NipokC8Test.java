package com.openbanking.psu.auth.spi.crypto.nipok;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.openbanking.psu.auth.spi.crypto.ec.ElisabethEd25519Group;
import com.openbanking.psu.auth.spi.model.Challenge;
import com.openbanking.psu.auth.spi.model.DiscreteLogCredential;
import com.openbanking.psu.auth.spi.model.NipokContext;
import com.openbanking.psu.auth.spi.model.NipokProof;
import com.openbanking.psu.auth.spi.wallet.SimulatorWalletProvider;
import com.openbanking.psu.auth.spi.wallet.SimulatorWalletProvider.CustodyMode;

/**
 * Conformance tests (Reviewer 1, Comment 8): test vectors and invalid cases of NIPoK-SE. Constants generated from
 * src/test/resources/nipok-test-vectors-v1.json (the same set checked independently with hashlib + libsodium). PURE, no I/O.
 */
class NipokC8Test {

  private final ElisabethEd25519Group ec = new ElisabethEd25519Group(null);
  private final NipokEngine engine = new NipokEngine(ec);

  // id, x, X, id_P, N, cb (empty = disabled), id_V, V, e, s, blob = base64url(N || V || s)
  private static final String[][] VALID = {
      {"TV1", "7f7f6ae1fc3f31f91102121937db596f4eebed770aaeffd052adbd14f600c908", "91c005f97121e4050d9f7877aa3f2621bd48ff5b3a93e274475c8d63396d9e58", "alice", "33c2861e89a8fd667a02304f23845966b8adca0ed847d1e150aac95b8a2287ba", "7e1ae90d7ccbf16c16e673a559c053e98815e89266caa39fb525736a7c926d41", "bank", "8818a07bb87f02dd761828724e00421a0a3cc2c1cc9e6fcf547cbff419298a8b", "71558d67a56ab54f8ebb742117ca64058f0b4c34dc5bfb297a55f97dfbab8103", "e0171f7c012bead75b625a167af1251f7e7784c36109360e213eeeee197f640c", "M8KGHomo_WZ6AjBPI4RZZrityg7YR9HhUKrJW4oih7qIGKB7uH8C3XYYKHJOAEIaCjzCwcyeb89UfL_0GSmKi-AXH3wBK-rXW2JaFnrxJR9-d4TDYQk2DiE-7u4Zf2QM"},
      {"TV2", "b349741eda1d30472abf326f94150d31ada77d3c35647827d71eb10f83b37801", "adfda51ae98b71093a60bac75c2cbc2da899bb91da6172925ca4511165611412", "bob", "3b8a2d7c597c296d8ac52b372fa58d19bf6e6c3ddb8cf41121278deecfae5904", "", "bank", "ee40e5337c0457c9856b6d74b4a5f6bae74d37c18c4d0dbb1e0557d35e6f6486", "158d77d5ce2b022f8b89ef2935c1e71ae1f22eb8470be697c070c975c1d2f70c", "ca8ebcd47cc98c45836a0c57cc2839a8a2a15ea9ca21aea7cf737537eeb7910d", "O4otfFl8KW2KxSs3L6WNGb9ubD3bjPQRISeN7s-uWQTuQOUzfARXyYVrbXS0pfa65003wYxNDbseBVfTXm9khsqOvNR8yYxFg2oMV8woOaiioV6pyiGup89zdTfut5EN"},
      {"TV3", "3a3478710bb0aefcb86b2382cdaf5906c5ef25f2ac615d93e187fe9ee813fd01", "dc41d3bdb8346d8a0d7d3b8833fb874df4251811426fc0f0247710f63f58bfcf", "người-dùng-01", "be8c20c79e5c5ae3c7c19770e1a091143a0023d2ac32703e5569fd0af74ac65f", "36be9f98c3dcf07acc7acbfe7b81181c6f6384daa75c0ca77fd3dfacc1340ae6", "https://bank.example/as", "1b9ac9953e453f517b2aa434caa76b0c5e87645a81a1a1bd99a4c45d0289be2f", "57f6fa0d54292715940998295d1c0f2dc96bab42008795035cda35dccc6a2c01", "4d32b04ccc77c5d7c8f191d0d39d2d4532f6885aa3bf9e6ab56868aec0a6a902", "vowgx55cWuPHwZdw4aCRFDoAI9KsMnA-VWn9CvdKxl8bmsmVPkU_UXsqpDTKp2sMXodkWoGhob2ZpMRdAom-L00ysEzMd8XXyPGR0NOdLUUy9ohao7-earVoaK7ApqkC"}
  };
  // id, X, V, s, id_P, N, cb, id_V, equation alone ("holds"/"fails")
  private static final String[][] INVALID = {
      {"IV01", "91c005f97121e4050d9f7877aa3f2621bd48ff5b3a93e274475c8d63396d9e58", "8818a07bb87f02dd761828724e00421a0a3cc2c1cc9e6fcf547cbff419298a8b", "cdeb14d91b8efc2f32ff51b958eb04347e7784c36109360e213eeeee197f641c", "alice", "33c2861e89a8fd667a02304f23845966b8adca0ed847d1e150aac95b8a2287ba", "7e1ae90d7ccbf16c16e673a559c053e98815e89266caa39fb525736a7c926d41", "bank", "holds"},
      {"IV02", "91c005f97121e4050d9f7877aa3f2621bd48ff5b3a93e274475c8d63396d9e58", "8818a07bb87f02dd761828724e00421a0a3cc2c1cc9e6fcf547cbff419298a8b", "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", "alice", "33c2861e89a8fd667a02304f23845966b8adca0ed847d1e150aac95b8a2287ba", "7e1ae90d7ccbf16c16e673a559c053e98815e89266caa39fb525736a7c926d41", "bank", "fails"},
      {"IV03", "91c005f97121e4050d9f7877aa3f2621bd48ff5b3a93e274475c8d63396d9e58", "8818a07bb87f02dd761828724e00421a0a3cc2c1cc9e6fcf547cbff419298a8b", "e1171f7c012bead75b625a167af1251f7e7784c36109360e213eeeee197f640c", "alice", "33c2861e89a8fd667a02304f23845966b8adca0ed847d1e150aac95b8a2287ba", "7e1ae90d7ccbf16c16e673a559c053e98815e89266caa39fb525736a7c926d41", "bank", "fails"},
      {"IV04", "91c005f97121e4050d9f7877aa3f2621bd48ff5b3a93e274475c8d63396d9e58", "8918a07bb87f02dd761828724e00421a0a3cc2c1cc9e6fcf547cbff419298a8b", "e0171f7c012bead75b625a167af1251f7e7784c36109360e213eeeee197f640c", "alice", "33c2861e89a8fd667a02304f23845966b8adca0ed847d1e150aac95b8a2287ba", "7e1ae90d7ccbf16c16e673a559c053e98815e89266caa39fb525736a7c926d41", "bank", "fails"},
      {"IV05", "91c005f97121e4050d9f7877aa3f2621bd48ff5b3a93e274475c8d63396d9e58", "e0171f7c012bead75b625a167af1251f7e7784c36109360e213eeeee197f640c", "8818a07bb87f02dd761828724e00421a0a3cc2c1cc9e6fcf547cbff419298a8b", "alice", "33c2861e89a8fd667a02304f23845966b8adca0ed847d1e150aac95b8a2287ba", "7e1ae90d7ccbf16c16e673a559c053e98815e89266caa39fb525736a7c926d41", "bank", "fails"},
      {"IV06", "91c005f97121e4050d9f7877aa3f2621bd48ff5b3a93e274475c8d63396d9e58", "8818a07bb87f02dd761828724e00421a0a3cc2c1cc9e6fcf547cbff419298a8b", "e0171f7c012bead75b625a167af1251f7e7784c36109360e213eeeee197f640c", "bob", "33c2861e89a8fd667a02304f23845966b8adca0ed847d1e150aac95b8a2287ba", "7e1ae90d7ccbf16c16e673a559c053e98815e89266caa39fb525736a7c926d41", "bank", "fails"},
      {"IV07", "91c005f97121e4050d9f7877aa3f2621bd48ff5b3a93e274475c8d63396d9e58", "8818a07bb87f02dd761828724e00421a0a3cc2c1cc9e6fcf547cbff419298a8b", "e0171f7c012bead75b625a167af1251f7e7784c36109360e213eeeee197f640c", "alice", "33c2861e89a8fd667a02304f23845966b8adca0ed847d1e150aac95b8a2287ba", "7e1ae90d7ccbf16c16e673a559c053e98815e89266caa39fb525736a7c926d41", "bank-b", "fails"},
      {"IV08", "91c005f97121e4050d9f7877aa3f2621bd48ff5b3a93e274475c8d63396d9e58", "8818a07bb87f02dd761828724e00421a0a3cc2c1cc9e6fcf547cbff419298a8b", "e0171f7c012bead75b625a167af1251f7e7784c36109360e213eeeee197f640c", "alice", "33c2861e89a8fd667a02304f23845966b8adca0ed847d1e150aac95b8a2287ba", "c8ce96b45640860ba5b5fb3bd7f69817f43a85f06cf82439aa8b883b5c44a07f", "bank", "fails"},
      {"IV09", "91c005f97121e4050d9f7877aa3f2621bd48ff5b3a93e274475c8d63396d9e58", "8818a07bb87f02dd761828724e00421a0a3cc2c1cc9e6fcf547cbff419298a8b", "e0171f7c012bead75b625a167af1251f7e7784c36109360e213eeeee197f640c", "alice", "33c2861e89a8fd667a02304f23845966b8adca0ed847d1e150aac95b8a2287ba", "", "bank", "fails"},
      {"IV10", "91c005f97121e4050d9f7877aa3f2621bd48ff5b3a93e274475c8d63396d9e58", "8818a07bb87f02dd761828724e00421a0a3cc2c1cc9e6fcf547cbff419298a8b", "e0171f7c012bead75b625a167af1251f7e7784c36109360e213eeeee197f640c", "alice", "2f5a1750dc48f354ec10756d8cdc672e9f693a1b7b44af2ded3d65e70f8d67e1", "7e1ae90d7ccbf16c16e673a559c053e98815e89266caa39fb525736a7c926d41", "bank", "fails"},
      {"IV11", "adfda51ae98b71093a60bac75c2cbc2da899bb91da6172925ca4511165611412", "8818a07bb87f02dd761828724e00421a0a3cc2c1cc9e6fcf547cbff419298a8b", "e0171f7c012bead75b625a167af1251f7e7784c36109360e213eeeee197f640c", "alice", "33c2861e89a8fd667a02304f23845966b8adca0ed847d1e150aac95b8a2287ba", "7e1ae90d7ccbf16c16e673a559c053e98815e89266caa39fb525736a7c926d41", "bank", "fails"}
  };
  private static final String BLOB_95_BYTES = "M8KGHomo_WZ6AjBPI4RZZrityg7YR9HhUKrJW4oih7qIGKB7uH8C3XYYKHJOAEIaCjzCwcyeb89UfL_0GSmKi-AXH3wBK-rXW2JaFnrxJR9-d4TDYQk2DiE-7u4Zf2Q";
  private static final String BLOB_STD_ALPHABET = "M8KGHomo/WZ6AjBPI4RZZrityg7YR9HhUKrJW4oih7qIGKB7uH8C3XYYKHJOAEIaCjzCwcyeb89UfL/0GSmKi+AXH3wBK+rXW2JaFnrxJR9+d4TDYQk2DiE+7u4Zf2QM";
  // id, X, expected outcome at registration
  private static final String[][] ENROLL = {
      {"KV01", "91c005f97121e4050d9f7877aa3f2621bd48ff5b3a93e274475c8d63396d9e58", "accept"},
      {"KV02", "0100000000000000000000000000000000000000000000000000000000000000", "reject"},
      {"KV03", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "reject"},
      {"KV04", "d086be7013b9505645b99bf257119e4eef77975891e27d04036746ab0dcd4f39", "reject"},
      {"KV05", "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "reject"},
      {"KV06", "0200000000000000000000000000000000000000000000000000000000000000", "reject"}
  };

  private static byte[] hx(String h) {
    byte[] o = new byte[h.length() / 2];
    for (int i = 0; i < o.length; i++) {
      o[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
    }
    return o;
  }

  private static NipokContext ctx(byte[] x, String idP, byte[] n, byte[] cb, String idV) {
    return new NipokContext(x, idP, n, cb.length == 0 ? null : cb, idV);
  }

  /** Check as specified: decoding stage (canonical s), then the equation. */
  private boolean specVerify(byte[] x, byte[] v, byte[] s, NipokContext c) {
    return NipokEncoding.isCanonicalScalar(s) && engine.verify(x, new NipokProof(v, s), c);
  }

  @Test
  void valid_vectors_reproduce_exactly_and_verify() {
    for (String[] t : VALID) {
      byte[] x = hx(t[1]);
      byte[] pub = hx(t[2]);
      NipokContext c = ctx(pub, t[3], hx(t[4]), hx(t[5]), t[6]);
      SimulatorWalletProvider resident = new SimulatorWalletProvider(x, ec, engine);
      SimulatorWalletProvider sealed = new SimulatorWalletProvider(x, CustodyMode.SEALED, ec, engine);
      assertThat(resident.publicPoint()).isEqualTo(pub);
      NipokProof p = resident.prove(c);
      assertThat(p.commitment()).isEqualTo(hx(t[7]));
      assertThat(engine.challenge(p.commitment(), c)).isEqualTo(hx(t[8]));
      assertThat(p.response()).isEqualTo(hx(t[9]));
      NipokProof q = sealed.prove(c);
      assertThat(q.commitment()).isEqualTo(p.commitment());
      assertThat(q.response()).isEqualTo(p.response());
      assertThat(specVerify(pub, p.commitment(), p.response(), c)).isTrue();
      assertThat(engine.verify(engine.prepare(pub), p, c)).isTrue();
      byte[] raw = Base64.getUrlDecoder().decode(t[10]);
      assertThat(raw.length == 96).isTrue();
      assertThat(Arrays.copyOfRange(raw, 0, 32)).isEqualTo(hx(t[4]));
      assertThat(Arrays.copyOfRange(raw, 32, 64)).isEqualTo(p.commitment());
      assertThat(Arrays.copyOfRange(raw, 64, 96)).isEqualTo(p.response());
      sealed.close();
    }
  }

  @Test
  void invalid_vectors_are_rejected() {
    for (String[] t : INVALID) {
      byte[] pub = hx(t[1]);
      NipokContext c = ctx(pub, t[4], hx(t[5]), hx(t[6]), t[7]);
      assertThat(specVerify(pub, hx(t[2]), hx(t[3]), c)).isFalse();
      // equation alone: only the vector s + l still satisfies it => the decoding stage is required
      assertThat(engine.verify(pub, new NipokProof(hx(t[2]), hx(t[3])), c)).isEqualTo("holds".equals(t[8]));
    }
  }

  @Test
  void malformed_blobs_are_rejected_at_decoding() {
    assertThat(Base64.getUrlDecoder().decode(BLOB_95_BYTES).length == 96).isFalse();
    boolean threw = false;
    try {
      Base64.getUrlDecoder().decode(BLOB_STD_ALPHABET);
    } catch (IllegalArgumentException e) {
      threw = true;
    }
    assertThat(threw).isTrue();
  }

  @Test
  void canonical_scalar_rule() {
    byte[] ell = hx("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    byte[] ellMinus1 = ell.clone();
    ellMinus1[0]--;
    byte[] ellPlus1 = ell.clone();
    ellPlus1[0]++;
    byte[] top = new byte[32];
    top[31] = (byte) 0x80;
    assertThat(NipokEncoding.isCanonicalScalar(new byte[32])).isTrue();
    assertThat(NipokEncoding.isCanonicalScalar(ellMinus1)).isTrue();
    assertThat(NipokEncoding.isCanonicalScalar(ell)).isFalse();
    assertThat(NipokEncoding.isCanonicalScalar(ellPlus1)).isFalse();
    assertThat(NipokEncoding.isCanonicalScalar(top)).isFalse();
    assertThat(NipokEncoding.isCanonicalScalar(new byte[31])).isFalse();
    assertThat(NipokEncoding.isCanonicalScalar(new byte[33])).isFalse();
    assertThat(NipokEncoding.isCanonicalScalar(null)).isFalse();
  }

  @Test
  void enrollment_key_vectors() {
    for (String[] k : ENROLL) {
      assertThat(NipokEncoding.isValidEnrollmentKey(hx(k[1]))).isEqualTo("accept".equals(k[2]));
    }
    assertThat(NipokEncoding.isValidEnrollmentKey(new byte[31])).isFalse();
    assertThat(NipokEncoding.isValidEnrollmentKey(null)).isFalse();
  }

  @Test
  void generic_verifier_port_fails_closed() {
    byte[] x = ec.hashToScalar("c8-generic-port".getBytes(StandardCharsets.UTF_8));
    SimulatorWalletProvider w = new SimulatorWalletProvider(x, ec, engine);
    byte[] n = new byte[32];
    NipokProof p = w.prove(new NipokContext(w.publicPoint(), "", n, null, ""));   // proof bound to no identity
    Challenge ch = new Challenge("c8", n, Instant.now(), Instant.now().plusSeconds(60), null);
    assertThat(new NipokVerifier(engine).verify(new DiscreteLogCredential(w.publicPoint()), p, ch).ok()).isFalse();
  }

  @Test
  void sealed_wallet_is_thread_safe() throws Exception {
    String[] t = VALID[0];
    byte[] x = hx(t[1]);
    NipokContext c = ctx(hx(t[2]), t[3], hx(t[4]), hx(t[5]), t[6]);
    SimulatorWalletProvider sealed = new SimulatorWalletProvider(x, CustodyMode.SEALED, ec, engine);
    byte[] wantV = hx(t[7]);
    byte[] wantS = hx(t[9]);
    int threads = 8;
    long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
    AtomicInteger errors = new AtomicInteger();
    AtomicInteger proofs = new AtomicInteger();
    ExecutorService ex = Executors.newFixedThreadPool(threads);
    List<Future<?>> fs = new ArrayList<>();
    for (int i = 0; i < threads; i++) {
      fs.add(ex.submit(() -> {
        while (System.nanoTime() < until) {
          try {
            NipokProof p = sealed.prove(c);
            if (!Arrays.equals(p.commitment(), wantV) || !Arrays.equals(p.response(), wantS)) {
              errors.incrementAndGet();
            }
            proofs.incrementAndGet();
          } catch (RuntimeException e) {
            errors.incrementAndGet();
          }
        }
      }));
    }
    for (Future<?> f : fs) {
      f.get();
    }
    ex.shutdown();
    sealed.close();
    assertThat(proofs.get() > 0).isTrue();
    assertThat(errors.get()).isEqualTo(0);
  }
}
