package com.vunetsystems.sms.client;

import com.google.gson.Gson;
import com.vunetsystems.sms.model.request.Notification;
import com.vunetsystems.sms.model.request.SearchAttribute;
import com.vunetsystems.sms.model.request.SendOTPRequest;
import com.vunetsystems.sms.model.request.ValidateOTPRequest;
import com.vunetsystems.sms.model.response.SendOTPResponse;
import com.vunetsystems.sms.model.response.ValidateOTPResponse;
import com.vunetsystems.sms.model.vunet.InternalResponse;
import com.vunetsystems.sms.service.SMSServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.http.HttpResponse;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.vunetsystems.sms.constants.Constants.*;
import static com.vunetsystems.sms.constants.Constants.SEND_ERROR_MESSAGE;

public class OTPClientImp implements OTPClient{
    Gson gson;

    public OTPClientImp() {
        gson = new Gson();
    }

    private static final Logger log = LoggerFactory.getLogger(OTPClientImp.class);

    @Override
    public InternalResponse sendOTP(String url, String username, String password, String applicationSecret, String applicationId, String serviceId, String emailTemplateId, String smsTemplateId, String clientName, String apiKey) throws Exception {
        InternalResponse responseObject = new InternalResponse();
        Map<String,String> headers = getSendOTPHeader(applicationId, serviceId, applicationSecret, apiKey);
        SendOTPRequest sendOTPRequest = getSendOTPRequest(username, emailTemplateId, smsTemplateId, password, clientName);
        String requestInJson = gson.toJson(sendOTPRequest);

        HttpResponse<String> response = HttpClientInternal.sendOtpPost(headers,requestInJson,url);

        if(response.statusCode() == 200){
            SendOTPResponse responseBody = gson.fromJson(response.body(), SendOTPResponse.class);
            if(isSendSuccessFull(responseBody)){
                responseObject.setID(SENT_SUCCESSFULLY_ID);
                responseObject.setMESSAGE(SUCCESS_RESPONSE);
            }else{
                log.error("Send OTP : Error returned from MFA server: " + response.body());
                responseObject.setID(SEND_ERROR_ID);
                responseObject.setMESSAGE(SEND_ERROR_MESSAGE);
            }
        }else{

            log.error("Send OTP Error returned from MFA server: " + response.body());

            responseObject.setID(SEND_ERROR_ID);
            responseObject.setMESSAGE(SEND_ERROR_MESSAGE);
        }

        return responseObject;
    }

    private boolean isSendSuccessFull(SendOTPResponse responseBody){
        boolean status = false;
        for(com.vunetsystems.sms.model.response.Notification notification : responseBody.getNotification()){
            if(notification.getStatus().equals("SUCCESS")){
                status = true;
            }
            break;
        }
        return status;
    }

    private SendOTPRequest getSendOTPRequest(String username, String emailTemplateId, String smsTemplateId, String password, String clientName){
        List<SearchAttribute> searchAttributes = new ArrayList<>();

        SearchAttribute searchAttribute = new SearchAttribute("USER_ID", username);
        searchAttributes.add(searchAttribute);

        List<Notification> notifications = new ArrayList<>();
        Notification emailNotification = generateNotificationMessage("EMAIL", emailTemplateId,clientName);
        Notification smsNotification = generateNotificationMessage("SMS", smsTemplateId,clientName);

        notifications.add(emailNotification);
        notifications.add(smsNotification);

        return new SendOTPRequest(searchAttributes,notifications,password);
    }

    private Notification generateNotificationMessage(String type, String templateID, String clientName) {
        Notification notification = new Notification();
        String message = String.format(OTP_EMAIL_MESSAGE, clientName);
        switch (type){
            case "EMAIL":
                notification.setNotificationType("EMAIL");
                notification.setMessageBody(message);
                notification.setTemplateId(templateID);
                break;
            case "SMS":
                notification.setNotificationType("SMS");
                notification.setMessageBody(message);
                notification.setTemplateId(templateID);
                break;
            default:
                notification.setNotificationType("SMS");
                notification.setMessageBody(message);
                notification.setTemplateId(DEFAULT_SMS_TEMPLATE);
        }

        return notification;
    }

    private Map<String,String> getSendOTPHeader(String applicationId, String serviceId, String applicationSecret, String apiKey){

        Map<String,String> headers = new HashMap<>();
        headers.put("Application-Id", applicationId);
        headers.put("Application-Secret", applicationSecret);
        headers.put("Services", serviceId);
        headers.put("Content-Type", "application/json");
        headers.put("apikey", apiKey);

        return headers;
    }

    @Override
    public InternalResponse validateOTP(String applicationId, String applicationSecret, String username, String otp, String url, String apiKey) throws Exception {
        InternalResponse responseObject = new InternalResponse();
        Map<String,String> headers = getValidateOTPHeader(applicationId, applicationSecret, apiKey);
        ValidateOTPRequest validateOTPRequest = getValidateOTPRequest(username,otp);
        String requestInJson = gson.toJson(validateOTPRequest);

        HttpResponse<String> response = HttpClientInternal.sendOtpPost(headers,requestInJson,url);

        ValidateOTPResponse validateOTPResponse = gson.fromJson(response.body(), ValidateOTPResponse.class);

        if(response.statusCode() == 200 && validateOTPResponse.getStatus().equals("SUCCESS")) {
            responseObject.setID(AUTHENTICATION_SUCCESS_ID);
            responseObject.setMESSAGE(AUTHENTICATION_SUCCESS_MESSAGE);
        }else if(response.statusCode() == 200 && validateOTPResponse.getStatus().equals("FAILED")){
            responseObject.setID(INVALID_OTP_ID);
            responseObject.setMESSAGE(validateOTPResponse.getErrorMessage());
        }else{
            log.error("Error returned from MFA server: " + response.body());
            responseObject.setID(GENERIC_ERROR_ID);
            responseObject.setMESSAGE(GENERIC_ERROR_MESSAGE);
        }

        return responseObject;
    }

    private Map<String,String> getValidateOTPHeader(String applicationID, String applicationSecret, String apiKey){

        Map<String,String> headers = new HashMap<>();
        headers.put("Application-Id", applicationID);
        headers.put("Application-Secret", applicationSecret);
        headers.put("Content-Type", "application/json");
        headers.put("apikey", apiKey);

        return headers;
    }

    private ValidateOTPRequest getValidateOTPRequest(String username, String otp) throws NoSuchPaddingException, IllegalBlockSizeException, CertificateException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

        ValidateOTPRequest validateOTPRequest = new ValidateOTPRequest();

        List<SearchAttribute> searchAttributes = new ArrayList<>();
        SearchAttribute searchAttribute = new SearchAttribute("USER_ID", username);
        searchAttributes.add(searchAttribute);

        validateOTPRequest.setAuthenticationToken(otp);
        validateOTPRequest.setSearchAttributes(searchAttributes);

        return validateOTPRequest;
    }
}
