package com.vunetsystems.sms.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vunetsystems.sms.client.*;
import com.vunetsystems.sms.constants.Constants;
import com.vunetsystems.sms.model.vunet.InternalResponse;
import com.vunetsystems.sms.util.Utilities;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.ConnectException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.vunetsystems.sms.constants.Constants.*;
import static com.vunetsystems.sms.constants.Constants.GENERIC_ERROR_MESSAGE;

public class SMSServiceImpl implements SMSService{
    private static final Logger log = LoggerFactory.getLogger(SMSServiceImpl.class);
    Utilities utilities;
    OTPClient otpClient;
    String isDevTrue;
    String applicationSecret;

    public SMSServiceImpl() {
        this.utilities = new Utilities();
        this.otpClient = new OTPClientImp();
        this.isDevTrue = System.getenv("DEV");
    }

    private String getDomainMappedUserName(AuthenticatorConfigModel config, String username) throws Exception{
        Map<String,String> domainMap = getDomainMap(config);

        for (Map.Entry<String, String> entry : domainMap.entrySet()) {
            String prefix = entry.getKey();
            String domain = entry.getValue();

            if (prefix.equals("DIGIT") && Character.isDigit(username.charAt(0))) {
                return username + domain;
            } else if (username.toUpperCase().startsWith(prefix)) {
                return username + domain;
            }
        }

        return username;
    }

    private Map<String, String> getDomainMap(AuthenticatorConfigModel config) throws JsonProcessingException {
        String domainMappingStr = config.getConfig().get("domainMapping");

        List<Map<String, String>> mappingList = new ArrayList<>();
        Map<String, String> domainMapping = new HashMap<>();

        if (domainMappingStr != null && !domainMappingStr.isEmpty()) {
            ObjectMapper objectMapper = new ObjectMapper();

            // Step 1: Deserialize JSON array to list of maps
            mappingList = objectMapper.readValue(domainMappingStr, new TypeReference<List<Map<String, String>>>() {});

            // Step 2: Convert list of key-value pairs into a map
            for (Map<String, String> entry : mappingList) {
                String key = entry.get("key");
                String value = entry.get("value");
                domainMapping.put(key, value);
            }
        }

        return domainMapping;
    }

    @Override
    public InternalResponse sendOTP(AuthenticationFlowContext context, AuthenticatorConfigModel config) {
        UserModel userModel = context.getUser();
        try{
            String url = config.getConfig().get("SendOTPURL");
            String username = getDomainMappedUserName(config,userModel.getUsername());
            String password = context.getAuthenticationSession().getAuthNote("user-password");
            applicationSecret = utilities.getRunningHash(config.getConfig().get("ApplicationSecret"));
            String applicationId = config.getConfig().get("ApplicationID");
            String serviceId = config.getConfig().get("ServiceID");
            String emailTemplateId = config.getConfig().get("EmailTemplateID");
            String smsTemplateId = config.getConfig().get("SMSTemplateID");
            String publicKeyString = config.getConfig().get("Token");
            String clientName = config.getAlias();
            String encryptedPassword = utilities.encryptString(password, publicKeyString);
            String apiKey = config.getConfig().get("apiKey");
            return otpClient.sendOTP(url,username,encryptedPassword,applicationSecret,applicationId,serviceId,emailTemplateId,smsTemplateId,clientName, apiKey);
        }catch (ConnectException e) {
            log.error("Failed to connect to OTP service", e);
            InternalResponse responseObject = new InternalResponse();
            responseObject.setID(GENERIC_ERROR_ID);
            responseObject.setMESSAGE(GENERIC_ERROR_MESSAGE);
            return responseObject;
        }
        catch (Exception e){
            log.error("Internal Server error in Sent OTP", e);
            InternalResponse responseObject = new InternalResponse();
            responseObject.setID(GENERIC_ERROR_ID);
            responseObject.setMESSAGE(GENERIC_ERROR_MESSAGE);
            return responseObject;
        }
    }

    @Override
    public InternalResponse validateOTP(AuthenticationFlowContext context, AuthenticatorConfigModel config, String otp) {
        InternalResponse responseObject = null;
        try{
            String API_URL = config.getConfig().get("ValidateOTPURL");
            String username = getDomainMappedUserName(config,context.getUser().getUsername());
            applicationSecret = utilities.getRunningHash(config.getConfig().get("ApplicationSecret"));
            String applicationId = config.getConfig().get("ApplicationID");
            String apiKey = config.getConfig().get("apiKey");
            String encryptedOTP = "";
            if(isDevTrue != null && isDevTrue.equals("True")){
                encryptedOTP = otp;
            }else{
                encryptedOTP = utilities.encryptString(otp,config.getConfig().get("Token"));
            }

            responseObject = otpClient.validateOTP(applicationId, applicationSecret,username,encryptedOTP,API_URL, apiKey);
        }catch (Exception e){
            log.error("Internal Server error in Validate OTP", e);
            responseObject = new InternalResponse();
            responseObject.setID(Constants.SEND_ERROR_ID);
            responseObject.setMESSAGE(Constants.SEND_ERROR_MESSAGE);
            return responseObject;
        }

        return responseObject;
    }
}
