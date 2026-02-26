package com.vunetsystems.authenticator.service;

import com.vunetsystems.authenticator.client.AuthenticatorClient;
import com.vunetsystems.authenticator.client.AuthenticatorClientImpl;
import com.vunetsystems.authenticator.model.InternalResponse;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;

public class AuthenticatorServiceImpl implements AuthenticatorService{

    AuthenticatorClient authenticatorClient;

    public AuthenticatorServiceImpl() {
        authenticatorClient = new AuthenticatorClientImpl();
    }

    @Override
    public InternalResponse validateOTP(AuthenticationFlowContext context, AuthenticatorConfigModel config, String otp) {
        String API_TOKEN = config.getConfig().get("Token");
        String API_URL = config.getConfig().get("URL");
        String username = context.getUser().getUsername();
        String CONTENT_TYPE = "application/json";
        String CHARACTER_ENCODING = "";

        return authenticatorClient.validateOTP(username,otp, API_URL, API_TOKEN, CONTENT_TYPE, CHARACTER_ENCODING);
    }
}
