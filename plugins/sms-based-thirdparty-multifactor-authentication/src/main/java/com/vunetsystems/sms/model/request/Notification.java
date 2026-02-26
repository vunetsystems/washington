
package com.vunetsystems.sms.model.request;

public class Notification {

    private String notificationType;
    private String messageBody;
    private String templateId;

    public Notification(String notificationType, String messageBody, String templateId) {
        this.notificationType = notificationType;
        this.messageBody = messageBody;
        this.templateId = templateId;
    }

    public Notification() {
    }

    public String getNotificationType() {
        return notificationType;
    }
    public void setNotificationType(String notificationType) {
        this.notificationType = notificationType;
    }
    public String getMessageBody() {
        return messageBody;
    }
    public void setMessageBody(String messageBody) {
        this.messageBody = messageBody;
    }
    public String getTemplateId() {
        return templateId;
    }
    public void setTemplateId(String templateId) {
        this.templateId = templateId;
    }

    @Override
    public String toString() {
        return "Notification{" +
                "notificationType='" + notificationType + '\'' +
                ", messageBody='" + messageBody + '\'' +
                ", templateId='" + templateId + '\'' +
                '}';
    }
}
