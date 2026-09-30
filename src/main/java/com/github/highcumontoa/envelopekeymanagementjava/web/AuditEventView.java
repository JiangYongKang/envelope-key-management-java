package com.github.highcumontoa.envelopekeymanagementjava.web;

import com.github.highcumontoa.envelopekeymanagementjava.audit.AuditEvent;

import java.time.Instant;

/**
 * 审计记录的对外视图。
 */
public class AuditEventView {

    private long id;
    private Instant timestamp;
    private String callerId;
    private String action;
    private String result;
    private String detail;

    public AuditEventView() {
    }

    public static AuditEventView from(AuditEvent event) {
        AuditEventView view = new AuditEventView();
        view.id = event.id();
        view.timestamp = event.timestamp();
        view.callerId = event.callerId();
        view.action = event.action().name();
        view.result = event.result();
        view.detail = event.detail();
        return view;
    }

    public long getId() {
        return id;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getCallerId() {
        return callerId;
    }

    public String getAction() {
        return action;
    }

    public String getResult() {
        return result;
    }

    public String getDetail() {
        return detail;
    }
}
