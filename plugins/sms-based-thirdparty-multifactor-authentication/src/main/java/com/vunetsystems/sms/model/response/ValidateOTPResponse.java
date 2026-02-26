
package com.vunetsystems.sms.model.response;

import java.util.List;

public class ValidateOTPResponse {

    private List<SearchAttribute> searchAttributes;
    private String status;
    private String errorMessage;

    public List<SearchAttribute> getSearchAttributes() {
        return searchAttributes;
    }

    public void setSearchAttributes(List<SearchAttribute> searchAttributes) {
        this.searchAttributes = searchAttributes;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

}
