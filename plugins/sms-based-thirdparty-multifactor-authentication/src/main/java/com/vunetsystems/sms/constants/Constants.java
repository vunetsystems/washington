package com.vunetsystems.sms.constants;

public class Constants {
    public static int SENT_SUCCESSFULLY_ID = 1;
    public static String SENT_SUCCESSFULLY_MESSAGE = "Successfully Sent SMS";
    public static int AUTHENTICATION_SUCCESS_ID = 2;
    public static String AUTHENTICATION_SUCCESS_MESSAGE = "Authentication Successful";
    public static int SEND_ERROR_ID = 3;
    public static String SEND_ERROR_MESSAGE = "Failed to send OTP";
    public static int GENERIC_ERROR_ID = 4;
    public static String GENERIC_ERROR_MESSAGE = "Something went wrong. Please try again later";
    public static int INVALID_OTP_ID = 5;
    public static String INVALID_OTP_MESSAGE = "Invalid OTP";
    public static String OTP_VALIDATION_WINDOW_OVER = "OTP has expired";
    public static String SUCCESS_RESPONSE = "SUCCESS";
    public static String OTP_EMAIL_MESSAGE = "Dear Customer, <OTP> is the OTP to LOGIN to %s Bank DIMFA. OTPs are SECRET. DO NOT disclose it to anyone. Bank NEVER asks for OTP.";
    public static String OTP_SMS_MESSAGE = "Dear Customer, <OTP> is the OTP to LOGIN to %s Bank DIMFA. OTPs are SECRET. DO NOT disclose it to anyone. Bank NEVER asks for OTP.";
    public static String DEFAULT_SMS_TEMPLATE = "TMPT1001";
    public static String DEFAULT_EMAIL_TEMPLATE = "TMPT1001";
    public static String OTP_TIMESTAMP = "otp-sent-time";
    public static String OTP_RETRY_COUNT = "otp-retry-count";


}
