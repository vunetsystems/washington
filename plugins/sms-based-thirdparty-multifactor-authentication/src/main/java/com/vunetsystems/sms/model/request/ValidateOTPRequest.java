
package com.vunetsystems.sms.model.request;

import java.util.List;

public class ValidateOTPRequest {

    private List<SearchAttribute> searchAttributes;
    private String authenticationToken;

    public List<SearchAttribute> getSearchAttributes() {
        return searchAttributes;
    }

    public void setSearchAttributes(List<SearchAttribute> searchAttributes) {
        this.searchAttributes = searchAttributes;
    }

    public ValidateOTPRequest() {
    }

    public String getAuthenticationToken() {
        return authenticationToken;
    }

    public void setAuthenticationToken(String authenticationToken) {
        this.authenticationToken = authenticationToken;
    }

    @Override
    public String toString() {
        return "ValidateOTPRequest{" +
                "searchAttributes=" + searchAttributes +
                ", authenticationToken='" + authenticationToken + '\'' +
                '}';
    }
}
