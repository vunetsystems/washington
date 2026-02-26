package com.vunetsystems.authenticator.model;

public class MFARequest {
    String uname;
    int uotp;
    String token;

    public MFARequest(String uname, int uotp, String token) {
        this.uname = uname;
        this.uotp = uotp;
        this.token = token;
    }

    public String getUname() {
        return uname;
    }

    public void setUname(String uname) {
        this.uname = uname;
    }

    public int getUotp() {
        return uotp;
    }

    public void setUotp(int uotp) {
        this.uotp = uotp;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
