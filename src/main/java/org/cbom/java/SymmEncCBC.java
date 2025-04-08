package org.cbom.java;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;

public class SymmEncCBC {
    public static void testAES() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        Key key = generator.generateKey();
        System.out.println("Key: " + Utils.toHexString(key.getEncoded()));

        // get IV
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] random = new byte[16];
        secureRandom.nextBytes(random);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(random);
        System.out.println("IV: " + Utils.toHexString(ivParameterSpec.getIV()));

        byte[] input = "Hello World".getBytes();
        System.out.println("Input: " + Utils.toHexString(input));

        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] encryptedOutput = cipher.doFinal(input);
        System.out.println("Encrypted output: " + Utils.toHexString(encryptedOutput));

        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byte[] decryptedOutput = cipher.doFinal(encryptedOutput);
        System.out.println("Decrypted output: " + Utils.toHexString(decryptedOutput));
    }
}
