package org.cbom.java;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import org.cbom.java.Utils;

public class SymmEncDemo {

    public static void testAES() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        Key key = generator.generateKey();
        System.out.println("Key: " + Utils.toHexString(key.getEncoded()));

        byte[] input = "Hello World".getBytes();
        System.out.println("Input: " + Utils.toHexString(input));

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedOutput = cipher.doFinal(input);
        System.out.println("Encrypted output: " + Utils.toHexString(encryptedOutput));

        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedOutput = cipher.doFinal(encryptedOutput);
        System.out.println("Decrypted output: " + Utils.toHexString(decryptedOutput));
    }
}
