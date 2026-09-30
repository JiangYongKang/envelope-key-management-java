package com.github.highcumontoa.envelopekeymanagementjava.auth;

import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * 调用方注册表（本地模拟，不依赖真实凭据）。
 *
 * <p>内置四个调用方，覆盖不同权限组合：</p>
 * <ul>
 *     <li>{@code app-crypto}：可加密、可解密；</li>
 *     <li>{@code app-encrypt-only}：仅可加密；</li>
 *     <li>{@code key-admin}：可轮换、可查审计；</li>
 *     <li>{@code auditor}：仅可查审计。</li>
 * </ul>
 */
@Component
public class CallerRegistry {

    private final Map<String, Caller> callers = new LinkedHashMap<>();

    public CallerRegistry() {
        register(new Caller("app-crypto", "业务服务：加解密",
                Set.of(Permission.ENCRYPT, Permission.DECRYPT)));
        register(new Caller("app-encrypt-only", "采集服务：仅加密",
                Set.of(Permission.ENCRYPT)));
        register(new Caller("key-admin", "密钥管理员：轮换与审计",
                Set.of(Permission.ROTATE, Permission.AUDIT_READ)));
        register(new Caller("auditor", "审计员：只读审计",
                Set.of(Permission.AUDIT_READ)));
    }

    private void register(Caller caller) {
        callers.put(caller.id(), caller);
    }

    /** 按 ID 查找调用方；未知 ID 返回 {@code null}。 */
    public Caller find(String callerId) {
        if (callerId == null) {
            return null;
        }
        return callers.get(callerId);
    }
}
