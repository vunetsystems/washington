package com.vunetsystems.sms.core;

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
public class ThirdPartySMSBasedMfaAuthenticatorFactory implements AuthenticatorFactory {

    private static final String PROVIDER_ID = "sms-auth-3rd-party-mfa";

    @Override
    public String getDisplayType() {
        return "SMS based Multi-factor Authentication";
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
        return "Authenticator that supports MFA with a third-party service otp.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {

        List<ProviderConfigProperty> configProperties = new ArrayList<>();

        // API Send OTP Endpoint Config
        ProviderConfigProperty sendAPIUrl = new ProviderConfigProperty();
        sendAPIUrl.setName("SendOTPURL");
        sendAPIUrl.setLabel("Server Address to send an OTP");
        sendAPIUrl.setType(ProviderConfigProperty.STRING_TYPE);
        sendAPIUrl.setHelpText("Enter the server details in the format: http://<server-ip>:<port>/<path> to send OTPs.");
        configProperties.add(sendAPIUrl);

        // API Validate OTP Endpoint Config
        ProviderConfigProperty validateOTPUrl = new ProviderConfigProperty();
        validateOTPUrl.setName("ValidateOTPURL");
        validateOTPUrl.setLabel("Server Address to validate an OTP");
        validateOTPUrl.setType(ProviderConfigProperty.STRING_TYPE);
        validateOTPUrl.setHelpText("Enter the server details in the format: http://<server-ip>:<port>/<path> to validate OTPs.");
        configProperties.add(validateOTPUrl);

        // Application-ID
        ProviderConfigProperty applicationID = new ProviderConfigProperty();
        applicationID.setName("ApplicationID");
        applicationID.setLabel("Application ID");
        applicationID.setType(ProviderConfigProperty.STRING_TYPE);
        applicationID.setHelpText("The unique identifier for the SMS application used by the gateway to route requests to the SMS server.");
        configProperties.add(applicationID);

        // Application-Secret
        ProviderConfigProperty applicationSecret = new ProviderConfigProperty();
        applicationSecret.setName("ApplicationSecret");
        applicationSecret.setLabel("Application Secret");
        applicationSecret.setType(ProviderConfigProperty.STRING_TYPE);
        applicationSecret.setHelpText("The SMS application secret key used by the gateway to authenticate SMS requests.");
        configProperties.add(applicationSecret);

        // Email Template ID
        ProviderConfigProperty emailTemplate = new ProviderConfigProperty();
        emailTemplate.setName("EmailTemplateID");
        emailTemplate.setLabel("Email Template ID");
        emailTemplate.setType(ProviderConfigProperty.STRING_TYPE);
        emailTemplate.setHelpText("Specifies the template used to format OTP-related emails.");
        configProperties.add(emailTemplate);

        // SMS Template ID
        ProviderConfigProperty smsTemplateId = new ProviderConfigProperty();
        smsTemplateId.setName("SMSTemplateID");
        smsTemplateId.setLabel("SMS Template ID");
        smsTemplateId.setType(ProviderConfigProperty.STRING_TYPE);
        smsTemplateId.setHelpText("Specifies the template used to format OTP-related SMS messages.");
        configProperties.add(smsTemplateId);

        // Service name
        ProviderConfigProperty serviceName = new ProviderConfigProperty();
        serviceName.setName("ServiceID");
        serviceName.setLabel("Service ID");
        serviceName.setType(ProviderConfigProperty.STRING_TYPE);
        serviceName.setHelpText("The identifier for the service responsible for sending and validating OTPs.");
        configProperties.add(serviceName);

        // API Key
        ProviderConfigProperty apiKey = new ProviderConfigProperty();
        apiKey.setName("apiKey");
        apiKey.setLabel("Api Key");
        apiKey.setType(ProviderConfigProperty.STRING_TYPE);
        apiKey.setHelpText("The API key that can be used to validate request");
        configProperties.add(apiKey);

        // API Timeout Config
        ProviderConfigProperty token = new ProviderConfigProperty();
        token.setName("Token");
        token.setLabel("Token");
        token.setType(ProviderConfigProperty.STRING_TYPE);
        token.setHelpText("The public key that can be used for encrypting credentials.");
        configProperties.add(token);

        //Domain mapping
        ProviderConfigProperty domainRules = new ProviderConfigProperty();
        domainRules.setName("domainMapping");
        domainRules.setLabel("Domain Mapping Rules");
        domainRules.setType(ProviderConfigProperty.MAP_TYPE);  // Key-value type
        domainRules.setHelpText("Map username prefix/pattern to email domain");
        configProperties.add(domainRules);

        //OTP Timeout
        ProviderConfigProperty otpTimeout = new ProviderConfigProperty();
        otpTimeout.setName("OTPTimeOut");
        otpTimeout.setLabel("OTP Time Out");
        otpTimeout.setType(ProviderConfigProperty.STRING_TYPE);
        otpTimeout.setHelpText("The duration (in seconds) after which an OTP expires.");
        configProperties.add(otpTimeout);

        //OTP RetryCount
        ProviderConfigProperty otpRetryCount = new ProviderConfigProperty();
        otpRetryCount.setName("OTPRetryCount");
        otpRetryCount.setLabel("OTP Retry Count");
        otpRetryCount.setType(ProviderConfigProperty.STRING_TYPE);
        otpRetryCount.setHelpText("The number of times a user can enter an incorrect OTP before it is blocked.");
        configProperties.add(otpRetryCount);

        return configProperties;
    }

    @Override
    public void close() {
        // NOOP
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new ThirdPartySMSMfaAuthenticator(session);
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
