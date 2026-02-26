package com.vunetsystems.sms.model.vunet;

public class InternalResponse {
    int ID;
    String MESSAGE;

    public InternalResponse(int ID, String MESSAGE) {
        this.ID = ID;
        this.MESSAGE = MESSAGE;
    }

    public InternalResponse() {
    }

    public int getID() {
        return ID;
    }

    public void setID(int ID) {
        this.ID = ID;
    }

    public String getMESSAGE() {
        return MESSAGE;
    }

    public void setMESSAGE(String MESSAGE) {
        this.MESSAGE = MESSAGE;
    }

    @Override
    public String toString() {
        return "ResponseObject{" +
                "ID=" + ID +
                ", MESSAGE='" + MESSAGE + '\'' +
                '}';
    }
}
