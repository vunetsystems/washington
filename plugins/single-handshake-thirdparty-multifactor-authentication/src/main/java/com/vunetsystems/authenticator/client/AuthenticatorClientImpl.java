package com.vunetsystems.authenticator.client;

import com.google.gson.Gson;
import com.vunetsystems.authenticator.constants.Constants;
import com.vunetsystems.authenticator.model.InternalResponse;
import com.vunetsystems.authenticator.model.MFARequest;
import com.vunetsystems.authenticator.model.MFAResponse;

import java.net.HttpURLConnection;
import java.net.http.HttpResponse;

import static com.vunetsystems.authenticator.constants.Constants.*;

public class AuthenticatorClientImpl implements AuthenticatorClient {
    Gson gson ;

    public AuthenticatorClientImpl() {
        this.gson = new Gson();
    }

    @Override
    public InternalResponse validateOTP(String username, String otp, String url, String apiToken, String contentType, String characterEncoding) {
        InternalResponse internalResponse = new InternalResponse();
        try {
            MFARequest request = new MFARequest(username,Integer.parseInt(otp),apiToken);
            String requestInJson = gson.toJson(request);

            HttpResponse<String> response = HttpClientInternal.sendPost(requestInJson, url, contentType, characterEncoding);
            MFAResponse response1 = gson.fromJson(response.body(), MFAResponse.class);

            if(response.statusCode() == HttpURLConnection.HTTP_OK && response1.getResponseCode() == HttpURLConnection.HTTP_OK && response1.isStatus()){
                internalResponse.setID(AUTHENTICATION_SUCCESS_ID);
                internalResponse.setMessage(AUTHENTICATION_SUCCESS_MESSAGE);
            }else if(response.statusCode() == HttpURLConnection.HTTP_OK && response1.getResponseCode() == HttpURLConnection.HTTP_OK &&response1.isUserRegistered()){
                internalResponse.setID(INVALID_OTP_ID);
                internalResponse.setMessage(INVALID_OTP_MESSAGE);
            }else if(response.statusCode() == HttpURLConnection.HTTP_OK && response1.getResponseCode() == HttpURLConnection.HTTP_OK && !response1.isUserRegistered()){
                internalResponse.setID(USER_NOT_FOUND_ERROR_ID);
                internalResponse.setMessage(USER_NOT_FOUND_ERROR_MESSAGE);
            }else{
                internalResponse.setID(GENERIC_ERROR_ID);
                internalResponse.setMessage(GENERIC_ERROR_MESSAGE);
            }
        }catch (Exception e) {
            internalResponse.setID(Constants.GENERIC_ERROR_ID);
            internalResponse.setMessage(GENERIC_ERROR_MESSAGE);
        }
        return internalResponse;
    }
}
