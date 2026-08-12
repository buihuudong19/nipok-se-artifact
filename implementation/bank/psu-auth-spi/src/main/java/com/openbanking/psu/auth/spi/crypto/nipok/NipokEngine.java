package com.openbanking.psu.auth.spi.crypto.nipok;

import com.openbanking.psu.auth.spi.crypto.ec.Ed25519Group;
import com.openbanking.psu.auth.spi.crypto.ec.ElisabethEd25519Group;
import com.openbanking.psu.auth.spi.crypto.ec.PreparedPoint;
import com.openbanking.psu.auth.spi.model.NipokContext;
import com.openbanking.psu.auth.spi.model.NipokProof;

/**
 * Lõi NIPoK (RFC 8235) THUẦN, THREAD-SAFE — phần KHÔNG bí mật: tính thách thức Fiat–Shamir + verify.
 * Dùng chung cho server (verify) và Wallet (để tính e khi prove).
 *
 * <p>{@code e = H(B ‖ V ‖ X ‖ proverId ‖ serverNonce ‖ channelBinding ‖ verifierId) mod ℓ}.
 * Verify: {@code V == s·B + e·X}.
 */
public final class NipokEngine {

  private final Ed25519Group ec;
  private final byte[] base;

  public NipokEngine(Ed25519Group ec) {
    this.ec = ec;
    this.base = ElisabethEd25519Group.basePoint();
  }

  /** Thách thức e (Fiat–Shamir) — prover và verifier tính ĐỘC LẬP ra cùng giá trị. */
  public byte[] challenge(byte[] commitmentV, NipokContext ctx) {
    return ec.hashToScalar(
        base,
        commitmentV,
        ctx.publicPoint(),
        ElisabethEd25519Group.utf8(ctx.proverId()),
        ctx.serverNonce(),
        ctx.channelBindingOrEmpty(),
        ElisabethEd25519Group.utf8(ctx.verifierId()));
  }

  /**
   * Verify proof: X hợp lệ (small-order guard) ∧ V == s·B + e·X.
   *
   * <p>OPT-1: guard small-order/identity đã GỘP vào {@link Ed25519Group#verifySchnorr} (giải nén X
   * MỘT lần dùng chung) ⟹ KHÔNG gọi {@code isValidPublicPoint} tách (vốn decompress + cofactor-mul +
   * 2 compress THỪA). X tại đây đến từ DB tin cậy (đã validate đầy đủ lúc enroll /psu/register), guard
   * trong verifySchnorr là defense-in-depth rẻ.
   */
  public boolean verify(byte[] publicPointX, NipokProof proof, NipokContext ctx) {
    byte[] e = challenge(proof.commitment(), ctx);
    return ec.verifySchnorr(publicPointX, proof.commitment(), proof.response(), e);
  }

  /**
   * OPT-A: tiền-tính X (credential PSU) → {@link PreparedPoint} tái dùng cho mọi verify của user đó
   * (elisabeth: bảng fixed-base comb; backend khác: fallback verify như cũ). Gọi 1 lần/credential.
   */
  public PreparedPoint prepare(byte[] publicPointX) {
    return ec.prepare(publicPointX);
  }

  /**
   * OPT-A verify: dùng X đã tiền-tính. Thách thức {@code e} vẫn tính Fiat–Shamir Y HỆT (đọc X-bytes
   * từ {@code ctx.publicPoint()}) ⟹ kết quả verify BẰNG đường {@link #verify(byte[], NipokProof,
   * NipokContext)}; chỉ khác chi phí EC (hai fixed-base comb thay 1 vartime-double-scalar + decompress).
   */
  public boolean verify(PreparedPoint prepared, NipokProof proof, NipokContext ctx) {
    byte[] e = challenge(proof.commitment(), ctx);
    return prepared.verifySchnorr(proof.commitment(), proof.response(), e);
  }

  public Ed25519Group group() { return ec; }
}
