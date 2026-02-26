package com.vunetsystems.authenticator.core;

import com.vunetsystems.authenticator.constants.Constants;
import com.vunetsystems.authenticator.model.InternalResponse;
import com.vunetsystems.authenticator.service.AuthenticatorService;
import com.vunetsystems.authenticator.service.AuthenticatorServiceImpl;
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

import static com.vunetsystems.authenticator.constants.Constants.*;

@JBossLog
public class ThirdPartySingleHandshakeMfaAuthenticator implements Authenticator {
    private final KeycloakSession session;
    private final AuthenticatorService authenticatorServiceImpl;

    public ThirdPartySingleHandshakeMfaAuthenticator(KeycloakSession session) {
        this.session = session;
        this.authenticatorServiceImpl = new AuthenticatorServiceImpl();
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel userModel = context.getUser();

        if(!isLdapUser(userModel, context)){
            context.success();
            return;
        }

        LoginFormsProvider form = context.form();
        Response challenge = form.createLoginTotp();
        context.challenge(challenge);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
        String otp = inputData.getFirst("otp");
        UserModel user = context.getUser();

        InternalResponse response = authenticatorServiceImpl.validateOTP(context,config, otp);

        if (response.getID() == Constants.AUTHENTICATION_SUCCESS_ID) {
            context.success();
        } else if (response.getID() == Constants.INVALID_OTP_ID) {
            Response challenge = context.form().setError(INVALID_OTP_MESSAGE).createLoginTotp();
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
        } else if (response.getID() == Constants.USER_NOT_FOUND_ERROR_ID) {
            Response challenge = context.form().setError(USER_NOT_FOUND_ERROR_MESSAGE).createLoginTotp();
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
        } else {
            Response challenge = context.form().setError(GENERIC_ERROR_MESSAGE).createLoginTotp();
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
        }
    }

    private boolean isLdapUser(UserModel user, AuthenticationFlowContext context) {
        return user.getFederationLink() != null; // If user is linked to an external provider (LDAP), return true
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
