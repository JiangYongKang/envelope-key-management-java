package com.github.highcumontoa.envelopekeymanagementjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 端到端 HTTP 集成测试：完整验证加解密、篡改/截断、轮换后旧密文可解、
 * 越权与参数错误的 HTTP 分类，以及审计接口可查询。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestPropertySource(properties = "ekm.local.dir=target/web-it-local-data")
class WebIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(WebIntegrationTest.class);

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate rest;

    private final ObjectMapper json = new ObjectMapper();

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private HttpHeaders jsonHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }

    @Test
    @Order(1)
    @DisplayName("加密->解密往返，且两次加密结果不同")
    void roundTrip() throws Exception {
        String first = encrypt("app-crypto", "端到端明文-123");
        String second = encrypt("app-crypto", "端到端明文-123");
        log.info("[关键输入] HTTP 同明文两次密文相等={}", first.equals(second));
        assertNotEquals(first, second);
        assertEquals("端到端明文-123", decrypt("app-crypto", first));
        assertEquals("端到端明文-123", decrypt("app-crypto", second));
    }

    @Test
    @Order(2)
    @DisplayName("轮换后：新密文用新版本，旧密文仍可解；旧版本密文可继续解密")
    void rotateThenDecryptOld() throws Exception {
        String oldCipher = encrypt("app-crypto", "轮换前-E2E");
        ResponseEntity<String> rotateResp = rest.postForEntity(
                url("/api/v1/keys/rotate"),
                new HttpEntity<>(json.writeValueAsString(Map.of("callerId", "key-admin")), jsonHeaders()),
                String.class);
        assertEquals(HttpStatus.OK, rotateResp.getStatusCode());
        int newVersion = json.readTree(rotateResp.getBody()).get("newVersion").asInt();
        log.info("[判定依据] HTTP 轮换成功 newVersion={}", newVersion);

        // 历史密文仍可用旧版本解出
        assertEquals("轮换前-E2E", decrypt("app-crypto", oldCipher));

        // 新密文必须使用新版本
        ResponseEntity<String> newEncResp = rest.postForEntity(url("/api/v1/encrypt"),
                new HttpEntity<>(json.writeValueAsString(Map.of(
                        "callerId", "app-crypto", "plaintext", "轮换后-E2E")), jsonHeaders()),
                String.class);
        JsonNode newEncBody = json.readTree(newEncResp.getBody());
        int kekVersion = newEncBody.get("masterKeyVersion").asInt();
        String newCipher = newEncBody.get("ciphertext").asText();
        log.info("[判定依据] 轮换后新密文 kekVersion={}，历史密文仍解密成功", kekVersion);
        assertEquals(newVersion, kekVersion);
        assertEquals("轮换后-E2E", decrypt("app-crypto", newCipher));
    }

    @Test
    @Order(3)
    @DisplayName("篡改密文 -> 400 CIPHERTEXT_TAMPERED(INTEGRITY)")
    void tamperedOverHttp() throws Exception {
        String cipher = encrypt("app-crypto", "http-篡改测试");
        byte[] raw = java.util.Base64.getDecoder().decode(cipher);
        // 翻转密文尾部一个字节（落在 GCM 标签区，结构保持完整）
        raw[raw.length - 2] ^= 0x01;
        String tampered = java.util.Base64.getEncoder().encodeToString(raw);
        ResponseEntity<String> resp = postDecrypt("app-crypto", tampered);
        JsonNode body = json.readTree(resp.getBody());
        log.info("[关键输入] HTTP 篡改密文 -> status={}, code={}, category={}",
                resp.getStatusCode(), body.get("code").asText(), body.get("category").asText());
        assertEquals(HttpStatus.BAD_REQUEST, resp.getStatusCode());
        assertEquals("CIPHERTEXT_TAMPERED", body.get("code").asText());
        assertEquals("INTEGRITY", body.get("category").asText());
    }

    @Test
    @Order(4)
    @DisplayName("截断密文 -> 400 CIPHERTEXT_TRUNCATED(CIPHERTEXT)")
    void truncatedOverHttp() throws Exception {
        String cipher = encrypt("app-crypto", "http-截断测试");
        ResponseEntity<String> resp = postDecrypt("app-crypto", cipher.substring(0, cipher.length() - 16));
        JsonNode body = json.readTree(resp.getBody());
        log.info("[关键输入] HTTP 截断密文 -> status={}, code={}", resp.getStatusCode(), body.get("code").asText());
        assertEquals(HttpStatus.BAD_REQUEST, resp.getStatusCode());
        assertEquals("CIPHERTEXT_TRUNCATED", body.get("code").asText());
    }

    @Test
    @Order(5)
    @DisplayName("引用不存在的密钥版本 -> 404 KEY_VERSION_NOT_FOUND(KEY)")
    void missingKeyVersionOverHttp() throws Exception {
        String cipher = encrypt("app-crypto", "http-缺失版本");
        byte[] raw = java.util.Base64.getDecoder().decode(cipher);
        byte[] fake = java.nio.ByteBuffer.allocate(4).putInt(999).array();
        System.arraycopy(fake, 0, raw, 5, 4);
        String changed = java.util.Base64.getEncoder().encodeToString(raw);
        ResponseEntity<String> resp = postDecrypt("app-crypto", changed);
        JsonNode body = json.readTree(resp.getBody());
        log.info("[关键输入] HTTP 伪造版本=999 -> status={}, code={}", resp.getStatusCode(), body.get("code").asText());
        assertEquals(HttpStatus.NOT_FOUND, resp.getStatusCode());
        assertEquals("KEY_VERSION_NOT_FOUND", body.get("code").asText());
    }

    @Test
    @Order(6)
    @DisplayName("越权：加密角色轮换 -> 403 ACCESS_DENIED(AUTHZ)，与 400 参数错误区分")
    void accessDeniedOverHttp() throws Exception {
        ResponseEntity<String> denied = rest.postForEntity(url("/api/v1/keys/rotate"),
                new HttpEntity<>(json.writeValueAsString(Map.of("callerId", "app-crypto")), jsonHeaders()),
                String.class);
        JsonNode deniedBody = json.readTree(denied.getBody());
        log.info("[关键输入] app-crypto 尝试轮换 -> status={}, code={}, category={}",
                denied.getStatusCode(), deniedBody.get("code").asText(), deniedBody.get("category").asText());
        assertEquals(HttpStatus.FORBIDDEN, denied.getStatusCode());
        assertEquals("ACCESS_DENIED", deniedBody.get("code").asText());

        ResponseEntity<String> badParam = rest.postForEntity(url("/api/v1/encrypt"),
                new HttpEntity<>(json.writeValueAsString(Map.of(
                        "callerId", "app-crypto", "plaintext", "  ")), jsonHeaders()),
                String.class);
        log.info("[关键输入] 空白明文 -> status={}", badParam.getStatusCode());
        assertEquals(HttpStatus.BAD_REQUEST, badParam.getStatusCode());
        assertEquals("INVALID_PARAMETER", json.readTree(badParam.getBody()).get("code").asText());

        // 未知调用方同样 403
        ResponseEntity<String> unknown = rest.postForEntity(url("/api/v1/encrypt"),
                new HttpEntity<>(json.writeValueAsString(Map.of(
                        "callerId", "ghost", "plaintext", "x")), jsonHeaders()),
                String.class);
        assertEquals(HttpStatus.FORBIDDEN, unknown.getStatusCode());
    }

    @Test
    @Order(7)
    @DisplayName("审计接口可查：包含 ENCRYPT/ROTATE/ACCESS_DENIED 记录且带时间")
    void auditQueryable() throws Exception {
        ResponseEntity<String> resp = rest.getForEntity(
                url("/api/v1/audit?callerId=key-admin"), String.class);
        assertEquals(HttpStatus.OK, resp.getStatusCode());
        JsonNode events = json.readTree(resp.getBody());
        assertTrue(events.isArray());
        assertTrue(events.size() > 0);
        boolean hasRotate = false;
        for (JsonNode event : events) {
            assertNotNull(event.get("timestamp").asText());
            assertNotNull(event.get("action").asText());
            if ("ROTATE".equals(event.get("action").asText())) {
                hasRotate = true;
            }
        }
        log.info("[判定依据] key-admin 可见审计记录 {} 条，含 ROTATE={}", events.size(), hasRotate);
        assertTrue(hasRotate, "轮换操作必须有审计记录");

        ResponseEntity<String> deniedEvents = rest.getForEntity(
                url("/api/v1/audit?callerId=key-admin&action=ACCESS_DENIED"), String.class);
        JsonNode denied = json.readTree(deniedEvents.getBody());
        log.info("[判定依据] ACCESS_DENIED 审计记录 {} 条", denied.size());
        assertTrue(denied.size() > 0, "被拒绝的请求必须留下审计记录");
    }

    private String encrypt(String caller, String plaintext) throws Exception {
        ResponseEntity<String> resp = rest.postForEntity(url("/api/v1/encrypt"),
                new HttpEntity<>(json.writeValueAsString(Map.of(
                        "callerId", caller, "plaintext", plaintext)), jsonHeaders()),
                String.class);
        assertEquals(HttpStatus.OK, resp.getStatusCode(), "加密应成功: " + resp.getBody());
        return json.readTree(resp.getBody()).get("ciphertext").asText();
    }

    private String decrypt(String caller, String ciphertext) throws Exception {
        ResponseEntity<String> resp = postDecrypt(caller, ciphertext);
        assertEquals(HttpStatus.OK, resp.getStatusCode(), "解密应成功: " + resp.getBody());
        return json.readTree(resp.getBody()).get("plaintext").asText();
    }

    private ResponseEntity<String> postDecrypt(String caller, String ciphertext) throws Exception {
        return rest.postForEntity(url("/api/v1/decrypt"),
                new HttpEntity<>(json.writeValueAsString(Map.of(
                        "callerId", caller, "ciphertext", ciphertext)), jsonHeaders()),
                String.class);
    }
}
