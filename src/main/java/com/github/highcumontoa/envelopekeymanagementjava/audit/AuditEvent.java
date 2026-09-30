package com.github.highcumontoa.envelopekeymanagementjava.audit;

import java.time.Instant;

/**
 * 一条不可变的审计记录。
 *
 * @param id        单调递增序号
 * @param timestamp 记录产生时间（UTC）
 * @param callerId  调用方标识；无法识别的调用方也原样记录
 * @param action    操作类型
 * @param result    结果（SUCCESS / FAILURE / DENIED）
 * @param detail    判定依据，例如错误码、KEK 版本、DEK ID
 */
public record AuditEvent(long id, Instant timestamp, String callerId,
                         AuditAction action, String result, String detail) {

    public static final String RESULT_SUCCESS = "SUCCESS";
    public static final String RESULT_FAILURE = "FAILURE";
    public static final String RESULT_DENIED = "DENIED";
}
