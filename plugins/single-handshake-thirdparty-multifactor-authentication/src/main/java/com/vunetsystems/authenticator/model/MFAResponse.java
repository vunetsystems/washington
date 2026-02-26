package com.vunetsystems.authenticator.model;

public class MFAResponse {
    boolean status;
    boolean userRegistered;
    int responseCode;

    public MFAResponse(boolean status, boolean userRegistered, int responseCode) {
        this.status = status;
        this.userRegistered = userRegistered;
        this.responseCode = responseCode;
    }

    public boolean isStatus() {
        return status;
    }

    public void setStatus(boolean status) {
        this.status = status;
    }

    public boolean isUserRegistered() {
        return userRegistered;
    }

    public void setUserRegistered(boolean userRegistered) {
        this.userRegistered = userRegistered;
    }

    public int getResponseCode() {
        return responseCode;
    }

    public void setResponseCode(int responseCode) {
        this.responseCode = responseCode;
    }
}
