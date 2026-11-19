package com.openbanking.services.aggregator.customer;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@SpringBootTest(webEnvironment = RANDOM_PORT)
class CustomerAggregatorServiceApplicationTests {

	@MockitoBean
	ReactiveJwtDecoder jwtDecoder;

	@Test
	void contextLoads() {
	}

}
