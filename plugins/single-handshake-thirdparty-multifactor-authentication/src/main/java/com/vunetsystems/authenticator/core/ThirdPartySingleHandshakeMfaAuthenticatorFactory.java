package com.vunetsystems.authenticator.core;

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
public class ThirdPartySingleHandshakeMfaAuthenticatorFactory implements AuthenticatorFactory {

    private static final String PROVIDER_ID = "auth-3rd-party-mfa";

    @Override
    public String getDisplayType() {
        return "Authenticator based Multi-factor Authentication[Single Handshake]";
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
        return "Authenticator that supports MFA with a third-party service.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {

        List<ProviderConfigProperty> configProperties = new ArrayList<>();

        // API Endpoint Config
        ProviderConfigProperty apiUrl = new ProviderConfigProperty();
        apiUrl.setName("URL");
        apiUrl.setLabel("URL");
        apiUrl.setType(ProviderConfigProperty.STRING_TYPE);
        apiUrl.setHelpText("The endpoint URL for third-party OTP validation.");
        configProperties.add(apiUrl);

        // API Timeout Config
        ProviderConfigProperty timeout = new ProviderConfigProperty();
        timeout.setName("Token");
        timeout.setLabel("Token");
        timeout.setType(ProviderConfigProperty.STRING_TYPE);
        timeout.setHelpText("Authentication Token");
        configProperties.add(timeout);

        return configProperties;
    }

    @Override
    public void close() {
        // NOOP
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new ThirdPartySingleHandshakeMfaAuthenticator(session);
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
