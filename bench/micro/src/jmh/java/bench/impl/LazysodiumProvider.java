package bench.impl;

import bench.Ed25519Provider;
import bench.KeyPairRaw;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.interfaces.Sign;

import java.util.Arrays;

/**
 * libsodium qua lazysodium-java (FFI = JNA). JNA dựa reflection → overhead/lần gọi CAO.
 * Đây là trường hợp để KIỂM CHỨNG giả thuyết "libsodium nhanh nhất" — rất có thể overhead JNA
 * kéo nó xuống so với Panama-FFM / Conscrypt cho thao tác ký nhỏ.
 */
public final class LazysodiumProvider implements Ed25519Provider {

    private LazySodiumJava ls;
    private byte[] sk64;   // libsodium secret key = seed(32) || pub(32)
    private byte[] pk32;
    private boolean ok;

    public LazysodiumProvider() {
        try { ls = new LazySodiumJava(new SodiumJava()); ok = true; }
        catch (Throwable t) { ok = false; }
    }

    @Override public String id() { return "libsodium-lazysodium-jna"; }
    @Override public boolean available() { return ok && ls != null; }

    @Override public KeyPairRaw generateKeyPair() {
        byte[] pk = new byte[Sign.PUBLICKEYBYTES];
        byte[] sk = new byte[Sign.SECRETKEYBYTES];
        ls.cryptoSignKeypair(pk, sk);
        byte[] seed = Arrays.copyOfRange(sk, 0, Sign.SEEDBYTES);  // libsodium sk = seed||pub
        return new KeyPairRaw(seed, pk);
    }

    @Override public void useKey(KeyPairRaw kp) {
        pk32 = kp.publicKey;
        sk64 = new byte[Sign.SECRETKEYBYTES];
        byte[] pkTmp = new byte[Sign.PUBLICKEYBYTES];
        ls.cryptoSignSeedKeypair(pkTmp, sk64, kp.seed);
    }

    @Override public byte[] sign(byte[] msg) {
        byte[] sig = new byte[Sign.BYTES];
        ls.cryptoSignDetached(sig, msg, msg.length, sk64);
        return sig;
    }

    @Override public boolean verify(byte[] sig, byte[] msg) {
        return ls.cryptoSignVerifyDetached(sig, msg, msg.length, pk32);
    }
}
