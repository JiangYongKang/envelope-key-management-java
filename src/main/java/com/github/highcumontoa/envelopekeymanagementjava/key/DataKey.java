package com.github.highcumontoa.envelopekeymanagementjava.key;

import java.time.Instant;

/** 数据密钥：以被主密钥包裹的形式持久化，使用时临时解包。 */
public record DataKey(String keyId,
                      int masterVersion,
                      byte[] wrappedKey,
                      byte[] wrappingIv,
                      Instant createdAt,
                      boolean enabled) {
}
