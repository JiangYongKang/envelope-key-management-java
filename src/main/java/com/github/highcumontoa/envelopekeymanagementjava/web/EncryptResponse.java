package com.github.highcumontoa.envelopekeymanagementjava.web;

public class EncryptResponse {
    private String ciphertext;
    private int masterKeyVersion;
    private String dataKeyId;

    public EncryptResponse() {
    }

    public EncryptResponse(String ciphertext, int masterKeyVersion, String dataKeyId) {
        this.ciphertext = ciphertext;
        this.masterKeyVersion = masterKeyVersion;
        this.dataKeyId = dataKeyId;
    }

    public String getCiphertext() {
        return ciphertext;
    }

    public int getMasterKeyVersion() {
        return masterKeyVersion;
    }

    public String getDataKeyId() {
        return dataKeyId;
    }
}
