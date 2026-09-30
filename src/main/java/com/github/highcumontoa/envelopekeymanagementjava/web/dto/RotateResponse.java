package com.github.highcumontoa.envelopekeymanagementjava.web.dto;

import java.time.Instant;

public record RotateResponse(int version, Instant createdAt, boolean coalesced) {
}
