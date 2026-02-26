package com.vunetsystems.authenticator.client;

import com.vunetsystems.authenticator.model.InternalResponse;

public interface AuthenticatorClient {
    public InternalResponse validateOTP(String username, String otp, String url, String apiToken, String contentType, String characterEncoding);
}
