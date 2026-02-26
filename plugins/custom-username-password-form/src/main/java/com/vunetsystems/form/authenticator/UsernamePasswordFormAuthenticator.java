package com.vunetsystems.form.authenticator;

import com.vunetsystems.form.service.CaptchaService;
import com.vunetsystems.form.service.PasswordService;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import static com.vunetsystems.form.constants.Constants.GENERIC_ERROR;

@JBossLog
public class UsernamePasswordFormAuthenticator extends UsernamePasswordForm {
    private final KeycloakSession session;
    private final String PRIVATE_KEY_PEM = System.getenv("PASSWORD_PUBLIC_RSA_KEY");
    private final CaptchaService captchaService = new CaptchaService();
    private final PasswordService passwordService = new PasswordService();

    public UsernamePasswordFormAuthenticator(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        try {
            AuthenticatorConfigModel config = context.getAuthenticatorConfig();
            MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
            String captchaInput = formData.getFirst("captcha");
            String captchaExpected = context.getAuthenticationSession().getAuthNote("captcha_expected");

            if (formData.containsKey("cancel")) {
                context.cancelLogin();
                return;
            }

            String encryptedPassword = formData.getFirst("password");
            String decryptedPassword = passwordService.decryptPassword(encryptedPassword);
            passwordService.updatePasswordField(formData, decryptedPassword);
            context.getAuthenticationSession().setAuthNote("user-password", decryptedPassword);

            if(isOfflineCaptchaEnabled(config)){
                if (captchaService.isValid(captchaInput, captchaExpected)) {
                    if (!validateForm(context, formData)) {
                        handleFailure(context, formData, "invalid_user_credentials", null);
                        return;
                    }
                } else {
                    handleFailure(context, formData, null, "Captcha entered is not valid");
                    return;
                }
            }else{
                if (!validateForm(context, formData)) {
                    handleFailure(context, formData, "invalid_user_credentials", null);
                    return;
                }
            }

            context.success();
        } catch (Exception e) {
            log.error("Unexpected error in form action", e);
            Response challenge = getGenericForm(context).setError(GENERIC_ERROR).createLoginUsernamePassword();
            context.challenge(challenge);
        }
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        LoginFormsProvider loginFormsProvider = getGenericForm(context);

        if (isOfflineCaptchaEnabled(config)) {
            setCaptcha(loginFormsProvider, context);
        }

        context.challenge(loginFormsProvider.createLoginUsernamePassword());
    }

    private void handleFailure(AuthenticationFlowContext context, MultivaluedMap<String, String> formData, String eventError, String formError) {
        if (eventError != null) {
            context.getEvent().error(eventError);
        }

        LoginFormsProvider loginFormsProvider = getGenericForm(context);
        if (formError != null) {
            loginFormsProvider.setError(formError);
        }

        if (isOfflineCaptchaEnabled(context.getAuthenticatorConfig())) {
            setCaptcha(loginFormsProvider, context);
        }

        context.challenge(loginFormsProvider.createLoginUsernamePassword());
    }

    private void setCaptcha(LoginFormsProvider loginFormsProvider, AuthenticationFlowContext context) {
        loginFormsProvider.setAttribute("captcha_enabled", true);
    }

    private boolean isOfflineCaptchaEnabled(AuthenticatorConfigModel config) {
        return config != null && "true".equalsIgnoreCase(config.getConfig().get("offline_captch"));
    }

    private LoginFormsProvider getGenericForm(AuthenticationFlowContext context) {
        String tabId = context.getAuthenticationSession().getTabId();

        return context.form().setAttribute("public_key", PRIVATE_KEY_PEM).setAttribute("tabId", tabId);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No-op
    }

    @Override
    public void close() {
        // No-op
    }

    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        return validateUserAndPassword(context, formData);
    }
}