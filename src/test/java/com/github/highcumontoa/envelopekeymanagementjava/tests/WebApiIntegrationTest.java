package com.github.highcumontoa.envelopekeymanagementjava.tests;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.file.Path;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 端到端：真实 Spring MVC 路径下验证 HTTP 状态、错误码分类与越权隔离。
 * 数据目录指向临时目录，重启测试互不污染。
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class WebApiIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(WebApiIntegrationTest.class);

    @TempDir
    static Path tempDir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("ekm.data-dir", () -> tempDir.toString());
    }

    @Autowired
    private MockMvc mockMvc;

    private static String savedCipher;

    @Test
    @Order(1)
    void encryptThenDecryptRoundTripViaHttp() throws Exception {
        MvcResult enc = mockMvc.perform(post("/api/keys/encrypt")
                        .header("X-Caller-Id", "svc-dec")
                        .contentType("application/json")
                        .content("{\"plaintext\":\"http-端到端-机密\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ciphertext").exists())
                .andReturn();
        String body = enc.getResponse().getContentAsString();
        savedCipher = body.replaceAll(".*\"ciphertext\":\"([^\"]+)\".*", "$1");
        log.info("关键输入: HTTP 加密返回密文={}", savedCipher.substring(0, 40) + "...");

        mockMvc.perform(post("/api/keys/decrypt")
                        .header("X-Caller-Id", "svc-dec")
                        .contentType("application/json")
                        .content("{\"ciphertext\":\"" + savedCipher + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.plaintext").value("http-端到端-机密"));
        log.info("[判定] HTTP 解密还原原文成功");
    }

    @Test
    @Order(2)
    void missingPermissionReturnsForbiddenDistinctFromBadRequest() throws Exception {
        // svc-enc 只有 ENCRYPT，尝试解密 -> 403 ACCESS_DENIED
        mockMvc.perform(post("/api/keys/decrypt")
                        .header("X-Caller-Id", "svc-enc")
                        .contentType("application/json")
                        .content("{\"ciphertext\":\"EKM1:x\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("ACCESS_DENIED"))
                .andDo(r -> log.info("[判定] 权限不足 => HTTP 403 ACCESS_DENIED: {}",
                        r.getResponse().getContentAsString()));

        // 无身份头 -> 同样 403 但原因不同
        mockMvc.perform(post("/api/keys/encrypt")
                        .contentType("application/json")
                        .content("{\"plaintext\":\"x\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("ACCESS_DENIED"))
                .andDo(r -> log.info("[判定] 缺失身份 => HTTP 403: {}",
                        r.getResponse().getContentAsString()));

        // 参数错误 -> 400 INVALID_PARAMETER，与 403 明确区分
        mockMvc.perform(post("/api/keys/encrypt")
                        .header("X-Caller-Id", "svc-dec")
                        .contentType("application/json")
                        .content("{\"plaintext\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("INVALID_PARAMETER"))
                .andDo(r -> log.info("[判定] 空明文 => HTTP 400 INVALID_PARAMETER: {}",
                        r.getResponse().getContentAsString()));
    }

    @Test
    @Order(3)
    void tamperedAndMalformedAndMissingVersionAreClassifiedOverHttp() throws Exception {
        // 篡改负载（翻转首段后会破坏 GCM）：构造一条真密文再改其负载首字符
        String c = savedCipher;
        char[] chars = c.toCharArray();
        int lastDot = c.lastIndexOf('.');
        chars[lastDot + 1] = chars[lastDot + 1] == 'A' ? 'B' : 'A';
        String tampered = new String(chars);

        mockMvc.perform(post("/api/keys/decrypt")
                        .header("X-Caller-Id", "svc-dec")
                        .contentType("application/json")
                        .content("{\"ciphertext\":\"" + tampered + "\"}"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.errorCode").value("CIPHERTEXT_TAMPERED"))
                .andDo(r -> log.info("[判定] 篡改密文 => HTTP 422: {}",
                        r.getResponse().getContentAsString()));

        mockMvc.perform(post("/api/keys/decrypt")
                        .header("X-Caller-Id", "svc-dec")
                        .contentType("application/json")
                        .content("{\"ciphertext\":\"not-a-cipher\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("CIPHERTEXT_MALFORMED"))
                .andDo(r -> log.info("[判定] 非法格式 => HTTP 400: {}",
                        r.getResponse().getContentAsString()));

        String missingVersion = c.replaceFirst("EKM1:\\d+\\.", "EKM1:9999.");
        mockMvc.perform(post("/api/keys/decrypt")
                        .header("X-Caller-Id", "svc-dec")
                        .contentType("application/json")
                        .content("{\"ciphertext\":\"" + missingVersion + "\"}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errorCode").value("KEY_VERSION_NOT_FOUND"))
                .andDo(r -> log.info("[判定] 引用不存在版本 => HTTP 404: {}",
                        r.getResponse().getContentAsString()));
    }

    @Test
    @Order(4)
    void rotateRequiresAdminAndAuditRequiresAuditor() throws Exception {
        // 普通账号尝试轮换 -> 403
        mockMvc.perform(post("/api/keys/rotate").header("X-Caller-Id", "svc-dec"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("ACCESS_DENIED"));

        // 管理员轮换成功
        mockMvc.perform(post("/api/keys/rotate").header("X-Caller-Id", "key-admin"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value(2))
                .andDo(r -> log.info("[判定] key-admin 轮换成功: {}",
                        r.getResponse().getContentAsString()));

        // 非审计账号读审计 -> 403；auditor -> 200 且能看到 ROTATE 记录
        mockMvc.perform(get("/api/keys/audit").header("X-Caller-Id", "svc-dec"))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/keys/audit").header("X-Caller-Id", "auditor"))
                .andExpect(status().isOk())
                .andDo(r -> log.info("[判定] auditor 查询审计成功，返回 {} 字节",
                        r.getResponse().getContentAsByteArray().length));
    }
}
