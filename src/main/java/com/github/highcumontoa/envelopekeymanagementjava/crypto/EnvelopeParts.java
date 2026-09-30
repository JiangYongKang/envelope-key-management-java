package com.github.highcumontoa.envelopekeymanagementjava.crypto;

/** 信封密文解析结果。 */
public record EnvelopeParts(String keyId,
                            int masterVersion,
                            byte[] wrappingIv,
                            byte[] wrappedDek,
                            byte[] payloadIv,
                            byte[] payloadCiphertext) {
}
