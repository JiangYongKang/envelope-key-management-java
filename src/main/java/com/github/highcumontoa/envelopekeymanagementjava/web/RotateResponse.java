package com.github.highcumontoa.envelopekeymanagementjava.web;

import java.time.Instant;

public class RotateResponse {
    private int newVersion;
    private Instant createdAt;

    public RotateResponse() {
    }

    public RotateResponse(int newVersion, Instant createdAt) {
        this.newVersion = newVersion;
        this.createdAt = createdAt;
    }

    public int getNewVersion() {
        return newVersion;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
