package com.github.highcumontoa.envelopekeymanagementjava.auth;

import java.util.Set;

/** 调用方身份及其权限集合（本地目录模拟）。 */
public record Caller(String id, String name, Set<Permission> permissions) {
}
