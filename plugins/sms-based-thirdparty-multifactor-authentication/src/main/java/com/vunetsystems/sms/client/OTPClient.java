package com.vunetsystems.sms.client;

import com.vunetsystems.sms.model.vunet.InternalResponse;

public interface OTPClient {
    public InternalResponse sendOTP(String url, String username, String password, String applicationSecret, String applicationId, String serviceId, String emailTemplateId, String smsTemplateId, String clientName, String apiKey) throws Exception;

    public InternalResponse validateOTP(String applicationId, String applicationSecret, String username, String otp, String url, String apiKey) throws Exception;
}
