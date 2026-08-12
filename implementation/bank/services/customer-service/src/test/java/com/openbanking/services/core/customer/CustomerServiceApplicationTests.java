package com.openbanking.services.core.customer;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.MongoDBContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@SpringBootTest(webEnvironment = RANDOM_PORT)
@Testcontainers
class CustomerServiceApplicationTests {

	@Container
	@ServiceConnection
	static MongoDBContainer mongodb = new MongoDBContainer("mongo:8.0.5");

	@Test
	void contextLoads() {
	}

}
