package com.vunetsystems.form.authenticator;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

@AutoService(AuthenticatorFactory.class)
public class UsernamePasswordFormAuthenticatorFactory implements AuthenticatorFactory {

    private static final String PROVIDER_ID = "custom-username-password-form";

    @Override
    public String getDisplayType() {
        return "Vunet's Username and Password form based";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Vunet Custom Username and Password form based authentication";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {

        List<ProviderConfigProperty> configProperties = new ArrayList<>();

        ProviderConfigProperty offlineCaptcha = new ProviderConfigProperty();
        offlineCaptcha.setName("offline_captch");
        offlineCaptcha.setLabel("Offline Captch");
        offlineCaptcha.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        offlineCaptcha.setHelpText("Enable offline captcha");
        offlineCaptcha.setDefaultValue("false");

        configProperties.add(offlineCaptcha);

        return configProperties;
    }

    @Override
    public void close() {
        // NOOP
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new UsernamePasswordFormAuthenticator(session);
    }

    @Override
    public void init(Config.Scope config) {
        // NOOP
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // NOOP
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
