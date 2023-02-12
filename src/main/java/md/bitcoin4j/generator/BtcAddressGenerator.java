package md.bitcoin4j.generator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.twostack.bitcoin4j.PrivateKey;
import org.twostack.bitcoin4j.address.Base58;
import org.twostack.bitcoin4j.address.LegacyAddress;
import md.bitcoin4j.generator.model.PrivateAddress;
import org.twostack.bitcoin4j.exception.InvalidKeyException;
import org.twostack.bitcoin4j.params.NetworkType;
import org.twostack.bitcoin4j.utils.BigIntegers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;

public class BtcAddressGenerator implements AddressGenerator {
    private BtcAddressGenerator() {}

    private static final BtcAddressGenerator INSTANCE = new BtcAddressGenerator();

    @Override
    public PrivateAddress generate(NetworkType networkType) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        var pair = createKeyPair();

        var publicECKey = (ECPublicKey) pair.getPublic();
        var privateECKey = (ECPrivateKey) pair.getPrivate();

        var w = publicECKey.getW();
        var s = BigIntegers.toNonLeadingZeroArray(privateECKey.getS());

        var address = createAddress(w, networkType);
        var wif = createWif(s, networkType);

        var publicAddress = LegacyAddress.fromString(networkType, address);
        var privateKey = PrivateKey.fromWIF(wif);

        return new PrivateAddress(publicAddress, privateKey);
    }

    private static KeyPair createKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        var ec = KeyPairGenerator.getInstance("EC");
        var curve = new ECGenParameterSpec("secp256k1");

        ec.initialize(curve);

        return ec.generateKeyPair();
    }

    private static String createAddress(ECPoint point, NetworkType networkType) throws NoSuchAlgorithmException, NoSuchProviderException {
        byte[] key;

        try (var out = new ByteArrayOutputStream()) {
            out.write(point.getAffineY().testBit(0) ? 3 : 2);
            out.writeBytes(BigIntegers.toNonLeadingZeroArray(point.getAffineX()));

            key = out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        var sha256Digest = MessageDigest.getInstance("SHA-256");
        var ripeMd160Digest = MessageDigest.getInstance("RipeMD160", BouncyCastleProvider.PROVIDER_NAME);

        var shaBytes = sha256Digest.digest(key);
        var ripedBytes = ripeMd160Digest.digest(shaBytes);

        var rmdBytes = new byte[ripedBytes.length + 1];
        rmdBytes[0] = (byte) ((networkType == NetworkType.MAIN) ? 0x00 : 0x6f);

        System.arraycopy(ripedBytes, 0, rmdBytes, 1, ripedBytes.length);

        var digestBytes = sha256Digest.digest(sha256Digest.digest(rmdBytes));

        var addressBytes = new byte[25];

        System.arraycopy(rmdBytes, 0, addressBytes, 0, rmdBytes.length);
        System.arraycopy(digestBytes, 0, addressBytes, 21, 4);

        return Base58.encode(addressBytes);
    }

    private static String createWif(byte[] privateKey, NetworkType networkType) throws NoSuchAlgorithmException {
        var sha256Digest = MessageDigest.getInstance("SHA-256");

        try (var out = new ByteArrayOutputStream()) {
            out.write((networkType == NetworkType.MAIN) ? 0x80 : 0xef);
            out.writeBytes(privateKey);
            out.write(0x01);

            var bytes = sha256Digest.digest(sha256Digest.digest(out.toByteArray()));
            var checkSum = Arrays.copyOfRange(bytes, 0, 4);

            out.writeBytes(checkSum);

            return Base58.encode(out.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static BtcAddressGenerator getInstance() {
        return INSTANCE;
    }
}
