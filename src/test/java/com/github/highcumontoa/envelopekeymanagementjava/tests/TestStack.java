package com.github.highcumontoa.envelopekeymanagementjava.tests;

import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditService;
import com.github.highcumontoa.envelopekeymanagementjava.auth.CallerDirectory;
import com.github.highcumontoa.envelopekeymanagementjava.crypto.CryptoService;
import com.github.highcumontoa.envelopekeymanagementjava.crypto.EnvelopeCodec;
import com.github.highcumontoa.envelopekeymanagementjava.service.EnvelopeEncryptionService;
import com.github.highcumontoa.envelopekeymanagementjava.service.KeyManagementService;
import com.github.highcumontoa.envelopekeymanagementjava.store.AuditStore;
import com.github.highcumontoa.envelopekeymanagementjava.store.DataKeyStore;
import com.github.highcumontoa.envelopekeymanagementjava.store.MasterKeyStore;

import java.nio.file.Path;
import java.util.function.Consumer;

/** 测试用完整服务栈，数据落在临时目录，不依赖任何外部服务。 */
record TestStack(Path dir,
                 CryptoService crypto,
                 EnvelopeCodec codec,
                 MasterKeyStore masterKeyStore,
                 DataKeyStore dataKeyStore,
                 AuditStore auditStore,
                 AuditService auditService,
                 CallerDirectory callerDirectory,
                 KeyManagementService kms,
                 EnvelopeEncryptionService encryption) {

    static TestStack create(Path dir) {
        CryptoService crypto = new CryptoService();
        EnvelopeCodec codec = new EnvelopeCodec(crypto);
        MasterKeyStore masterStore = new MasterKeyStore(dir.toString());
        DataKeyStore dataStore = new DataKeyStore(dir.toString());
        AuditStore auditStoreFile = new AuditStore(dir.toString());
        AuditService audit = new AuditService(auditStoreFile);
        KeyManagementService kms = new KeyManagementService(masterStore, dataStore, crypto, audit);
        EnvelopeEncryptionService enc = new EnvelopeEncryptionService(
                kms, dataStore, crypto, codec, audit);
        return new TestStack(dir, crypto, codec, masterStore, dataStore, auditStoreFile,
                audit, new CallerDirectory(), kms, enc);
    }

    /** 构造一个把“新版本落盘前”动作替换为 hook 的 KMS（用于轮换并发测试）。 */
    static TestStack createWithRotationHook(Path dir, Consumer<KeyManagementService> beforeAppendHook) {
        CryptoService crypto = new CryptoService();
        EnvelopeCodec codec = new EnvelopeCodec(crypto);
        MasterKeyStore masterStore = new MasterKeyStore(dir.toString());
        DataKeyStore dataStore = new DataKeyStore(dir.toString());
        AuditStore auditStoreFile = new AuditStore(dir.toString());
        AuditService audit = new AuditService(auditStoreFile);
        KeyManagementService kms = new KeyManagementService(
                masterStore, dataStore, crypto, audit) {
            @Override
            protected void onBeforeAppend() {
                beforeAppendHook.accept(this);
            }
        };
        EnvelopeEncryptionService enc = new EnvelopeEncryptionService(
                kms, dataStore, crypto, codec, audit);
        return new TestStack(dir, crypto, codec, masterStore, dataStore, auditStoreFile,
                audit, new CallerDirectory(), kms, enc);
    }
}
