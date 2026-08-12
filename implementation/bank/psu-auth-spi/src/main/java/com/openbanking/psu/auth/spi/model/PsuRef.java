package com.openbanking.psu.auth.spi.model;

import java.util.UUID;

/** Tham chiếu danh tính PSU (đã phân giải từ username/cert). */
public record PsuRef(UUID customerId, String username) {}
