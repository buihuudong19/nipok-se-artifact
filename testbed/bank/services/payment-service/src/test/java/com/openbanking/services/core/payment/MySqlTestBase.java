package com.openbanking.services.core.payment;

import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.MySQLContainer;

public abstract class MySqlTestBase {

    @ServiceConnection
    static final MySQLContainer<?> database = new MySQLContainer<>("mysql:9.2.0")
        .withStartupTimeoutSeconds(300);

    static {
        database.start();
    }
}
