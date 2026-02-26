package com.vunetsystems.sms.core;

import com.vunetsystems.sms.model.vunet.InternalResponse;
import com.vunetsystems.sms.service.SMSService;
import com.vunetsystems.sms.service.SMSServiceImpl;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.time.Instant;

import static com.vunetsystems.sms.constants.Constants.*;

@JBossLog
public class ThirdPartySMSMfaAuthenticator implements Authenticator {
    private final KeycloakSession session;
    private final SMSService smsService;

    public ThirdPartySMSMfaAuthenticator(KeycloakSession session) {
        this.session = session;
        this.smsService = new SMSServiceImpl();
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel userModel = context.getUser();
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        AuthenticationSessionModel sessionModel = context.getAuthenticationSession();

        if (!isLdapUser(userModel, context)) {
            context.success();
            return;
        }

        InternalResponse responseObject = smsService.sendOTP(context, config);

        LoginFormsProvider formProvider = context.form();
        Response challenge;


        switch (responseObject.getID()) {
            case 1:
                context.getAuthenticationSession().removeAuthNote("user-password");
                long timestamp = Instant.now().getEpochSecond();
                sessionModel.setAuthNote(OTP_TIMESTAMP, String.valueOf(timestamp));
                sessionModel.setAuthNote(OTP_RETRY_COUNT, String.valueOf(0));
                challenge = formProvider.createLoginTotp();
                context.challenge(challenge);
                return;
            case 3:
                challenge = context.form().setError(SEND_ERROR_MESSAGE).createLoginTotp();
                context.failureChallenge(AuthenticationFlowError.IDENTITY_PROVIDER_ERROR, challenge);
                return;
            case 4:
                challenge = context.form().setError(SEND_ERROR_MESSAGE).createLoginTotp();
                context.failureChallenge(AuthenticationFlowError.IDENTITY_PROVIDER_ERROR, challenge);
                return;
            default:
                challenge = context.form().setError(GENERIC_ERROR_MESSAGE).createLoginTotp();
                context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
                context.cancelLogin();
        }
    }

    @Override
    public void action(AuthenticationFlowContext context){
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
        String otp = inputData.getFirst("otp");
        AuthenticationSessionModel sessionModel = context.getAuthenticationSession();

        long sendTime = Long.parseLong(sessionModel.getAuthNote(OTP_TIMESTAMP));
        int otpRetryCount = Integer.parseInt(sessionModel.getAuthNote(OTP_RETRY_COUNT));

        int retryCount = Integer.parseInt(config.getConfig().get("OTPRetryCount"));
        long expiryTime = Long.parseLong(config.getConfig().get("OTPTimeOut"));

        long currentTimestamp = Instant.now().getEpochSecond();
        if(currentTimestamp - sendTime < expiryTime && otpRetryCount < retryCount){
            sessionModel.setAuthNote(OTP_RETRY_COUNT, String.valueOf(++otpRetryCount));
            InternalResponse responseObject = validateOTPExternal(context,otp,config);

            if (responseObject.getID() == AUTHENTICATION_SUCCESS_ID) {
                context.success();
            } else if (responseObject.getID() == INVALID_OTP_ID) {
                Response challenge = context.form().setError(INVALID_OTP_MESSAGE).createLoginTotp();
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            } else {
                Response challenge = context.form().setError(GENERIC_ERROR_MESSAGE).createLoginTotp();
                context.failureChallenge(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR, challenge);
            }
        }else{
            Response challenge = context.form().setError(OTP_VALIDATION_WINDOW_OVER).createLoginTotp();
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
        }
    }

    private boolean isLdapUser(UserModel user, AuthenticationFlowContext context) {
        return user.getFederationLink() != null; // If user is linked to an external provider (LDAP), return true
    }

    private InternalResponse validateOTPExternal(AuthenticationFlowContext context, String password, AuthenticatorConfigModel config) {
        return smsService.validateOTP(context, config, password);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

    @Override
    public void close() {}
}
