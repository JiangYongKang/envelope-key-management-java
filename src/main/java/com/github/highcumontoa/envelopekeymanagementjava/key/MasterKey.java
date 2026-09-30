package com.github.highcumontoa.envelopekeymanagementjava.key;

import java.time.Instant;

/**
 * 主密钥（KEK，本地存储模拟）（骨架）。
 */
public class MasterKey {

    private final int version;
    private final byte[] rawKey;
    private final Instant createdAt;

    public MasterKey(int version, byte[] rawKey, Instant createdAt) {
        this.version = version;
        this.rawKey = rawKey;
        this.createdAt = createdAt;
    }

    public int getVersion() {
        return version;
    }

    public byte[] getRawKey() {
        return rawKey;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
