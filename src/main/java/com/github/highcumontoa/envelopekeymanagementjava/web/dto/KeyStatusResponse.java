package com.github.highcumontoa.envelopekeymanagementjava.web.dto;

import java.util.List;

public record KeyStatusResponse(int currentVersion, List<Integer> versions) {
}
