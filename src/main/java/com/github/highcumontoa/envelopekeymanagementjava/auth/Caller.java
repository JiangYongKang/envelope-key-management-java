package com.github.highcumontoa.envelopekeymanagementjava.auth;

import java.util.Set;

/**
 * 调用方身份及其不可变权限集合。
 */
public record Caller(String id, String description, Set<Permission> permissions) {

    public Caller {
        permissions = Set.copyOf(permissions);
    }

    public boolean has(Permission permission) {
        return permissions.contains(permission);
    }
}
