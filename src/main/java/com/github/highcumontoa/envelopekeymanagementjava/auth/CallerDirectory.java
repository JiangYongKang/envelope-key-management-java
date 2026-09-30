package com.github.highcumontoa.envelopekeymanagementjava.auth;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 本地调用方目录，用静态配置模拟身份系统，无真实凭据。
 * <ul>
 *   <li>{@code svc-enc}：仅加密</li>
 *   <li>{@code svc-dec}：加密 + 解密</li>
 *   <li>{@code key-admin}：轮换 + 加密 + 解密</li>
 *   <li>{@code auditor}：只读审计</li>
 *   <li>{@code svc-limited}：无任何权限，用于演示拒绝</li>
 * </ul>
 */
public class CallerDirectory {

    private final Map<String, Caller> callers = new LinkedHashMap<>();

    public CallerDirectory() {
        register("svc-enc", "加密服务账号", Set.of(Permission.ENCRYPT));
        register("svc-dec", "加解密服务账号", Set.of(Permission.ENCRYPT, Permission.DECRYPT));
        register("key-admin", "密钥管理员",
                Set.of(Permission.ENCRYPT, Permission.DECRYPT, Permission.ROTATE));
        register("auditor", "审计只读账号", Set.of(Permission.AUDIT_READ));
        register("svc-limited", "无权限演示账号", Set.of());
    }

    private void register(String id, String name, Set<Permission> permissions) {
        callers.put(id, new Caller(id, name, Set.copyOf(permissions)));
    }

    public Optional<Caller> find(String callerId) {
        if (callerId == null || callerId.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(callers.get(callerId));
    }

    public List<Caller> all() {
        return List.copyOf(callers.values());
    }
}
