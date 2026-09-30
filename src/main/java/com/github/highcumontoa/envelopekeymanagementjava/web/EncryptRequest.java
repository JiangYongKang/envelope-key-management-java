package com.github.highcumontoa.envelopekeymanagementjava.web;

public class EncryptRequest {
    private String callerId;
    private String plaintext;

    public String getCallerId() {
        return callerId;
    }

    public void setCallerId(String callerId) {
        this.callerId = callerId;
    }

    public String getPlaintext() {
        return plaintext;
    }

    public void setPlaintext(String plaintext) {
        this.plaintext = plaintext;
    }
}
