package com.example;

import supranational.blst.*;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public final class BlsVerifyApp {
    private static final HexFormat HEX = HexFormat.of();

    private static final String DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    private static final byte[] KEYGEN_SALT = "BLS-SIG-KEYGEN-SALT-".getBytes(StandardCharsets.UTF_8);

    private static final byte[] MESSAGE = HEX.parseHex(
            "4f141c7a717531632b4f0f002f110e6f38722b1c137b1874076450681f686c5b" +
                    "47172f1a4d4b2b6407102776510c3c2c59133c102306606a344f666a4751227e" +
                    "000000017b210707055b331143154d666d6d5960382439222a65400070774b0e" +
                    "20062c4b5b475178404a2a483020211f0a024f2770761728406d713942560a0e" +
                    "697a553f"
    );

    private BlsVerifyApp() {
    }

    public static void main(String[] args) {
        SecretKey[] secretKeys = {
                mkSecretKey(0),
                mkSecretKey(1)
        };

        byte[][] publicKeys = new byte[secretKeys.length][];
        byte[][] signatures = new byte[secretKeys.length][];

        for (int i = 0; i < secretKeys.length; i++) {
            P1 publicKey = new P1(secretKeys[i]);
            if (!publicKey.in_group()) throw new IllegalStateException("Public key #" + i + " is not in G1 subgroup");
            publicKeys[i] = publicKey.compress();

            P2 signature = new P2().hash_to(MESSAGE, DST).sign_with(secretKeys[i]);
            if (!signature.in_group()) throw new IllegalStateException("Signature #" + i + " is not in G2 subgroup");
            signatures[i] = signature.compress();
        }

        P1_Affine aggregatedPublicKey = aggregatePublicKeys(publicKeys);
        P2_Affine aggregatedSignature = aggregateSignatures(signatures);

        Pairing pairing = new Pairing(true, DST);

        BLST_ERROR err = pairing.aggregate(aggregatedPublicKey, aggregatedSignature, MESSAGE);
        if (err != BLST_ERROR.BLST_SUCCESS) throw new RuntimeException("Can't aggregate, " + err);

        pairing.commit();
        boolean verified = pairing.finalverify();

        System.out.println("message      = 0x" + HEX.formatHex(MESSAGE));
        System.out.println("publicKey[0] = 0x" + HEX.formatHex(publicKeys[0]));
        System.out.println("publicKey[1] = 0x" + HEX.formatHex(publicKeys[1]));
        System.out.println("signature[0] = 0x" + HEX.formatHex(signatures[0]));
        System.out.println("signature[1] = 0x" + HEX.formatHex(signatures[1]));
        System.out.println("aggPk        = 0x" + HEX.formatHex(aggregatedPublicKey.compress()));
        System.out.println("aggSig       = 0x" + HEX.formatHex(aggregatedSignature.compress()));
        System.out.println("verified     = " + verified);

        if (!verified) throw new IllegalStateException("Aggregated BLS signature verification failed");
    }

    private static SecretKey mkSecretKey(int i) {
        SecretKey secretKey = new SecretKey();

        byte[] ikm = new byte[33];
        for (int j = 0; j < 32; j++) ikm[j] = 1;
        ikm[32] = (byte) i;

        secretKey.keygen_v5(ikm, KEYGEN_SALT);
        return secretKey;
    }

    private static P1_Affine aggregatePublicKeys(byte[][] publicKeys) {
        P1 sum = new P1();

        for (int i = 0; i < publicKeys.length; i++) {
            P1 publicKey = new P1(publicKeys[i]);
            if (!publicKey.in_group()) throw new IllegalStateException("Public key #" + i + " is not in G1 subgroup");
            sum.add(publicKey);
        }

        P1_Affine aggregatedPublicKey = sum.to_affine();
        if (!aggregatedPublicKey.in_group())
            throw new IllegalStateException("Aggregated public key is not in G1 subgroup");

        return aggregatedPublicKey;
    }

    private static P2_Affine aggregateSignatures(byte[][] signatures) {
        P2 sum = new P2();

        for (int i = 0; i < signatures.length; i++) {
            P2 signature = new P2(signatures[i]);
            if (!signature.in_group()) throw new IllegalStateException("Signature #" + i + " is not in G2 subgroup");
            sum.add(signature);
        }

        P2_Affine aggregatedSignature = sum.to_affine();
        if (!aggregatedSignature.in_group())
            throw new IllegalStateException("Aggregated signature is not in G2 subgroup");

        return aggregatedSignature;
    }
}