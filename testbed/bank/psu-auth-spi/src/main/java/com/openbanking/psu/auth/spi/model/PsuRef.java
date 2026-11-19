package com.openbanking.psu.auth.spi.model;

import java.util.UUID;

/** Reference to a PSU identity (resolved from the user name/certificate). */
public record PsuRef(UUID customerId, String username) {}
