package com.github.highcumontoa.envelopekeymanagementjava.web;

public class DecryptResponse {
    private String plaintext;

    public DecryptResponse() {
    }

    public DecryptResponse(String plaintext) {
        this.plaintext = plaintext;
    }

    public String getPlaintext() {
        return plaintext;
    }
}
