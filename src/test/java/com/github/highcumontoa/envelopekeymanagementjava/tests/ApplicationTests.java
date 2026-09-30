package com.github.highcumontoa.envelopekeymanagementjava.tests;

import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditService;
import com.github.highcumontoa.envelopekeymanagementjava.crypto.EnvelopeCryptoService;
import com.github.highcumontoa.envelopekeymanagementjava.key.KeyManagementService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Spring 上下文冒烟测试：所有 Bean 可装配，首版本主密钥自动初始化。
 */
@SpringBootTest
@TestPropertySource(properties = "ekm.local.dir=target/context-local-data")
class ApplicationTests {

    @Autowired
    private KeyManagementService keyManagementService;
    @Autowired
    private EnvelopeCryptoService envelopeCryptoService;
    @Autowired
    private AuditService auditService;

    @Test
    void contextLoadsAndInitialMasterKeyReady() {
        assertNotNull(keyManagementService);
        assertNotNull(envelopeCryptoService);
        assertNotNull(auditService);
        assertNotNull(keyManagementService.currentMasterKey());
    }
}
