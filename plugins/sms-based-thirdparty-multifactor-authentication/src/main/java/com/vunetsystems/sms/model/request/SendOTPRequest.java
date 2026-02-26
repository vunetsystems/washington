
package com.vunetsystems.sms.model.request;

import java.util.List;

public class SendOTPRequest {

    private List<SearchAttribute> searchAttributes;
    private List<Notification> notification;
    private String password;

    public SendOTPRequest(List<SearchAttribute> searchAttributes, List<Notification> notification, String password) {
        this.searchAttributes = searchAttributes;
        this.notification = notification;
        this.password = password;
    }

    public List<SearchAttribute> getSearchAttributes() {
        return searchAttributes;
    }

    public void setSearchAttributes(List<SearchAttribute> searchAttributes) {
        this.searchAttributes = searchAttributes;
    }

    public List<Notification> getNotification() {
        return notification;
    }

    public void setNotification(List<Notification> notification) {
        this.notification = notification;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
