package com.vunetsystems.sms.service;

import com.vunetsystems.sms.model.vunet.InternalResponse;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;

public interface SMSService {

    public InternalResponse sendOTP(AuthenticationFlowContext context, AuthenticatorConfigModel config);

    public InternalResponse validateOTP(AuthenticationFlowContext context, AuthenticatorConfigModel model, String OTP);
}
