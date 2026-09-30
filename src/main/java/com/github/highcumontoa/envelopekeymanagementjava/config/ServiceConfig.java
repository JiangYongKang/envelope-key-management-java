package com.github.highcumontoa.envelopekeymanagementjava.config;

import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditService;
import com.github.highcumontoa.envelopekeymanagementjava.auth.CallerDirectory;
import com.github.highcumontoa.envelopekeymanagementjava.crypto.CryptoService;
import com.github.highcumontoa.envelopekeymanagementjava.crypto.EnvelopeCodec;
import com.github.highcumontoa.envelopekeymanagementjava.service.AuthorizationService;
import com.github.highcumontoa.envelopekeymanagementjava.service.EnvelopeEncryptionService;
import com.github.highcumontoa.envelopekeymanagementjava.service.KeyManagementService;
import com.github.highcumontoa.envelopekeymanagementjava.store.AuditStore;
import com.github.highcumontoa.envelopekeymanagementjava.store.DataKeyStore;
import com.github.highcumontoa.envelopekeymanagementjava.store.MasterKeyStore;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** 本地装配：全部组件均为进程内实现，不依赖任何外部服务或真实凭据。 */
@Configuration
public class ServiceConfig {

    @Bean
    public CryptoService cryptoService() {
        return new CryptoService();
    }

    @Bean
    public EnvelopeCodec envelopeCodec(CryptoService cryptoService) {
        return new EnvelopeCodec(cryptoService);
    }

    @Bean
    public MasterKeyStore masterKeyStore(@Value("${ekm.data-dir:./data}") String dataDir) {
        return new MasterKeyStore(dataDir);
    }

    @Bean
    public DataKeyStore dataKeyStore(@Value("${ekm.data-dir:./data}") String dataDir) {
        return new DataKeyStore(dataDir);
    }

    @Bean
    public AuditStore auditStore(@Value("${ekm.data-dir:./data}") String dataDir) {
        return new AuditStore(dataDir);
    }

    @Bean
    public CallerDirectory callerDirectory() {
        return new CallerDirectory();
    }

    @Bean
    public AuditService auditService(AuditStore auditStore) {
        return new AuditService(auditStore);
    }

    @Bean
    public AuthorizationService authorizationService(CallerDirectory callerDirectory,
                                                      AuditService auditService) {
        return new AuthorizationService(callerDirectory, auditService);
    }

    @Bean
    public KeyManagementService keyManagementService(MasterKeyStore masterKeyStore,
                                                     DataKeyStore dataKeyStore,
                                                     CryptoService cryptoService,
                                                     AuditService auditService) {
        return new KeyManagementService(masterKeyStore, dataKeyStore, cryptoService, auditService);
    }

    @Bean
    public EnvelopeEncryptionService envelopeEncryptionService(KeyManagementService keyManagementService,
                                                               DataKeyStore dataKeyStore,
                                                               CryptoService cryptoService,
                                                               EnvelopeCodec envelopeCodec,
                                                               AuditService auditService) {
        return new EnvelopeEncryptionService(
                keyManagementService, dataKeyStore, cryptoService, envelopeCodec, auditService);
    }
}
