package org.cbom.java;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hash {
    public static void hashText(String s) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] input = s.getBytes();
        byte[] digest = messageDigest.digest(input);
        System.out.println("Input: " + s);
        StringBuilder hexString = new StringBuilder();
        for (byte b : digest) {
            hexString.append(String.format("%02x", b));
        }
        System.out.println("Digest: " + hexString);
    }
}
