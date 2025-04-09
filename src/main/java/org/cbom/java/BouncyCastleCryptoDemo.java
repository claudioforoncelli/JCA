package org.cbom.java;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Date;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.asn1.x500.X500Name;

public class BouncyCastleCryptoDemo {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // RSA key pair generation
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        // AES encryption/decryption
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES", "BC");
        aesKeyGen.init(256);
        SecretKey aesKey = aesKeyGen.generateKey();

        byte[] ivBytes = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ivBytes);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] plaintext = "Secret Message".getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);

        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        byte[] decrypted = cipher.doFinal(ciphertext);

        // SHA-256 hash
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256", "BC");
        byte[] hash = sha256.digest("message".getBytes());

        // HMAC with SHA-256
        Mac hmac = Mac.getInstance("HmacSHA256", "BC");
        hmac.init(aesKey);
        byte[] hmacBytes = hmac.doFinal("auth message".getBytes());

        // Signature (RSA)
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initSign(keyPair.getPrivate());
        signature.update("signed message".getBytes());
        byte[] sigBytes = signature.sign();

        signature.initVerify(keyPair.getPublic());
        signature.update("signed message".getBytes());
        boolean verified = signature.verify(sigBytes);

        // PBKDF2 Key Derivation
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec("password".toCharArray(), salt, 65536, 256);
        SecretKey derivedKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

        // Self-signed certificate using modern API
        X500Name issuer = new X500Name("CN=Test Cert");
        X500Name subject = issuer;
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 10000);
        Date notAfter = new Date(System.currentTimeMillis() + 1000000000);

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                notBefore,
                notAfter,
                subject,
                keyPair.getPublic()
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider("BC").build(keyPair.getPrivate());
        X509CertificateHolder holder = certBuilder.build(signer);

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream certStream = new ByteArrayInputStream(holder.getEncoded());
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(certStream);

        System.out.println("Bouncy Castle demo complete.");
    }
}
