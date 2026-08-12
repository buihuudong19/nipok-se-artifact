package com.openbanking.services.tpp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@ConfigurationPropertiesScan
@EnableScheduling   // G5 — JarmJwksFetcher refresh định kỳ JWKS
public class TppServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(TppServiceApplication.class, args);
	}

}
