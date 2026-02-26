package com.vunetsystems.authenticator.model;

public class InternalResponse {
    private int ID;
    private String Message;

    public InternalResponse() {
    }

    public int getID() {
        return ID;
    }

    public void setID(int ID) {
        this.ID = ID;
    }

    public String getMessage() {
        return Message;
    }

    public void setMessage(String message) {
        Message = message;
    }

    @Override
    public String toString() {
        return "InternalResponse{" +
                "ID=" + ID +
                ", Message='" + Message + '\'' +
                '}';
    }
}
