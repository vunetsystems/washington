package com.vunetsystems.form.utilities;

import jakarta.ws.rs.core.MultivaluedMap;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class Utilities {

    private static final String PRIVATE_KEY_PEM = System.getenv("PASSWORD_PRIVATE_RSA_KEY");

    public static String decrypt(String encrypted) throws Exception {
        encrypted = java.net.URLDecoder.decode(encrypted, StandardCharsets.UTF_8);

        // 2. Clean PEM
        String privateKeyPEM = PRIVATE_KEY_PEM
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        // 3. Convert PKCS#1 (RSA PRIVATE KEY) to PKCS#8 (if needed)
        // OR use BouncyCastle to support PKCS#1 (see notes below)

        byte[] keyBytes = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(keySpec);

        // 4. Decode encrypted password (Base64) and decrypt
        byte[] encryptedBytes = Base64.getDecoder().decode(encrypted);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void updatePassword(MultivaluedMap<String, String> formData, String decryptedPassword){
        List<String> passwords = new ArrayList<>();
        passwords.add(decryptedPassword);
        formData.remove("password");
        formData.put("password", passwords);
    }
}