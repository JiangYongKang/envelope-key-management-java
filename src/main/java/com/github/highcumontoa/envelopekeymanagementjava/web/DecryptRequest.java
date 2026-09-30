package com.github.highcumontoa.envelopekeymanagementjava.web;

public class DecryptRequest {
    private String callerId;
    private String ciphertext;

    public String getCallerId() {
        return callerId;
    }

    public void setCallerId(String callerId) {
        this.callerId = callerId;
    }

    public String getCiphertext() {
        return ciphertext;
    }

    public void setCiphertext(String ciphertext) {
        this.ciphertext = ciphertext;
    }
}
