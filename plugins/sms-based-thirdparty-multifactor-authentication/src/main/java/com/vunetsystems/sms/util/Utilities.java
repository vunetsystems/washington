package com.vunetsystems.sms.util;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.lang.reflect.UndeclaredThrowableException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Locale;
import java.util.Random;

public class Utilities {
    public String getRunningHash(String applicationSecret){
        Random random = new Random();
        char[] buf = new char[20];
        String upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String lower = upper.toLowerCase(Locale.ROOT);
        String digits = "0123456789";
        String alphanum = upper + lower + digits;
        char[] symbols = alphanum.toCharArray();
        for (int idx = 0; idx < buf.length; ++idx)
            buf[idx] = symbols[random.nextInt(symbols.length)];
        String randomSalt = new String(buf);
        String applicationSecretePlainText = applicationSecret;
        applicationSecretePlainText = applicationSecretePlainText + randomSalt;
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException e) {
            throw new UndeclaredThrowableException(e);
        }
        String generatedHash = Base64.getEncoder().encodeToString(messageDigest.digest(applicationSecretePlainText.getBytes()));
        String applicationSecrete = randomSalt + generatedHash;

        return applicationSecrete;
    }

    public String encryptString(String password, String publicKeyString) throws CertificateException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String base64Certificate = publicKeyString
                .replaceAll("-----BEGIN CERTIFICATE-----", "")
                .replaceAll("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", ""); // Remove whitespace/newlines

        byte[] certificateBytes = Base64.getDecoder().decode(base64Certificate);

        ByteArrayInputStream bais = new ByteArrayInputStream(certificateBytes);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(bais);

        PublicKey publicKey = cert.getPublicKey();
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] secretMessageBytes = password.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);

        return Base64.getEncoder().encodeToString(encryptedMessageBytes);
    }
}
