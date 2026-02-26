package com.vunetsystems.authenticator.service;

import com.vunetsystems.authenticator.model.InternalResponse;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;

public interface AuthenticatorService {
    public InternalResponse validateOTP(AuthenticationFlowContext context, AuthenticatorConfigModel config, String otp);
}
