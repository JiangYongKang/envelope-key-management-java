package com.github.highcumontoa.envelopekeymanagementjava.key;

import java.time.Instant;

/**
 * 数据密钥（DEK，明文只在内存中短暂存在）（骨架）。
 */
public class DataKey {

    private final String id;
    private final int masterKeyVersion;
    private final byte[] plaintextKey;
    private final byte[] encryptedKey;
    private final Instant createdAt;

    public DataKey(String id, int masterKeyVersion, byte[] plaintextKey, byte[] encryptedKey, Instant createdAt) {
        this.id = id;
        this.masterKeyVersion = masterKeyVersion;
        this.plaintextKey = plaintextKey;
        this.encryptedKey = encryptedKey;
        this.createdAt = createdAt;
    }

    public String getId() {
        return id;
    }

    public int getMasterKeyVersion() {
        return masterKeyVersion;
    }

    public byte[] getPlaintextKey() {
        return plaintextKey;
    }

    public byte[] getEncryptedKey() {
        return encryptedKey;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
