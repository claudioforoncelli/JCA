package org.cbom.java;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class NistRulesDemo {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        SecureRandom random = new SecureRandom();

        byte[] plaintext = "Confidential Data!".getBytes();

        // SHA-1 and SHA-224
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1", "BC");
        MessageDigest sha224 = MessageDigest.getInstance("SHA-224", "BC");
        System.out.println("SHA-1: " + Hex.toHexString(sha1.digest(plaintext)));
        System.out.println("SHA-224: " + Hex.toHexString(sha224.digest(plaintext)));

        // TDEA (Triple DES)
        KeyGenerator tdeaKeyGen = KeyGenerator.getInstance("DESede", "BC");
        tdeaKeyGen.init(168);
        SecretKey tdeaKey = tdeaKeyGen.generateKey();
        runCipher("DESede/CBC/PKCS5Padding", tdeaKey, plaintext, random);

        // AES with key sizes and multiple modes
        int[] keySizes = {128, 192, 256};
        String[] modes = {"ECB", "CBC", "CFB", "OFB", "CTR", "GCM", "CCM"};

        for (int keySize : keySizes) {
            KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES", "BC");
            aesKeyGen.init(keySize);
            SecretKey aesKey = aesKeyGen.generateKey();

            for (String mode : modes) {
                String transformation = mode.equals("ECB") ?
                        "AES/" + mode + "/PKCS5Padding" :
                        mode.equals("GCM") || mode.equals("CCM") ?
                                "AES/" + mode + "/NoPadding" :
                                "AES/" + mode + "/PKCS5Padding";

                try {
                    runCipher(transformation, aesKey, plaintext, random);
                } catch (Exception e) {
                    System.out.println("Skipped mode: " + mode + " (" + e.getMessage() + ")");
                }
            }
        }

        // AES-XTS - requires 2 * key size and no padding
        try {
            System.out.println("Testing AES/XTS/NoPadding:");
            KeyGenerator xtsKeyGen = KeyGenerator.getInstance("AES", "BC");
            xtsKeyGen.init(256);
            SecretKey key1 = xtsKeyGen.generateKey();
            SecretKey key2 = xtsKeyGen.generateKey();

            byte[] combinedKey = new byte[64];
            System.arraycopy(key1.getEncoded(), 0, combinedKey, 0, 32);
            System.arraycopy(key2.getEncoded(), 0, combinedKey, 32, 32);

            SecretKey xtsKey = new SecretKeySpec(combinedKey, "AES");

            Cipher xtsCipher = Cipher.getInstance("AES/XTS/NoPadding", "BC");
            IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
            xtsCipher.init(Cipher.ENCRYPT_MODE, xtsKey, ivSpec);
            byte[] padded = Arrays.copyOf(plaintext, 32); // XTS requires block-aligned input
            byte[] xtsEncrypted = xtsCipher.doFinal(padded);
            System.out.println("AES/XTS/NoPadding: " + Hex.toHexString(xtsEncrypted));
        } catch (Exception e) {
            System.out.println("AES-XTS not supported: " + e.getMessage());
        }

        // FF3 Format-Preserving Encryption
        try {
            System.out.println("FF3 encryption not included in standard BC — use FPE library.");
        } catch (Exception e) {
            System.out.println("FF3 Error: " + e.getMessage());
        }

        System.out.println("All tests complete.");
    }

    private static void runCipher(String transformation, SecretKey key, byte[] data, SecureRandom random) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation, "BC");
        byte[] ivBytes = new byte[cipher.getBlockSize() > 0 ? cipher.getBlockSize() : 12]; // 12 bytes for GCM
        random.nextBytes(ivBytes);

        if (transformation.contains("GCM")) {
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        } else if (transformation.contains("CCM")) {
            AlgorithmParameterSpec ccmSpec = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, key, ccmSpec);
        } else if (transformation.contains("ECB")) {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } else {
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        }

        byte[] encrypted = cipher.doFinal(data);
        System.out.println(transformation + ": " + Hex.toHexString(encrypted));
    }
}
