package com.vunetsystems.form.service;

import com.vunetsystems.form.utilities.Utilities;
import jakarta.ws.rs.core.MultivaluedMap;

public class PasswordService {

    public String decryptPassword(String encryptedPassword) throws Exception {
        return Utilities.decrypt(encryptedPassword.trim());
    }

    public void updatePasswordField(MultivaluedMap<String, String> formData, String decryptedPassword) {
        Utilities.updatePassword(formData, decryptedPassword);
    }
}