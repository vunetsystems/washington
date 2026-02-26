package com.vunetsystems.form.service;

public class CaptchaService {
    
    public boolean isValid(String input, String expected) {
        return expected != null && expected.equalsIgnoreCase(input);
    }
}