
package com.vunetsystems.sms.model.response;

import java.util.List;
import com.vunetsystems.sms.model.request.SearchAttribute;

public class SendOTPResponse {

    private List<SearchAttribute> searchAttributes;
    private List<Notification> notification;

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

}
