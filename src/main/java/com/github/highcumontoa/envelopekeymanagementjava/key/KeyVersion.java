package com.github.highcumontoa.envelopekeymanagementjava.key;

import java.time.Instant;

/**
 * 一个主密钥版本。主密钥为层级模型的顶层：
 * 主密钥 (MK) 加密包裹数据密钥 (DEK)，DEK 加密实际业务负载。
 */
public record KeyVersion(int version, byte[] masterKey, Instant createdAt, boolean enabled) {
}
