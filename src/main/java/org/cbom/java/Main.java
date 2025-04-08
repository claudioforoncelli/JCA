package org.cbom.java;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        System.out.println("=== BEGIN HASH TEST ===");
        Hash.hashText("Hello World");
        System.out.println("=== END HASH TEST === \n");

        System.out.println("=== BEGIN SYMMETRIC ENCRYPTION TEST AES-ECB ===");
        SymmEncECB.testAES();
        System.out.println("=== END SYMMETRIC ENCRYPTION TEST AES-ECB === \n");

        System.out.println("=== BEGIN SYMMETRIC ENCRYPTION TEST AES-CBC ===");
        SymmEncCBC.testAES();
        System.out.println("=== END SYMMETRIC ENCRYPTION TEST AES-CBC === \n");
    }

}