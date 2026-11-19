package com.openbanking.services.tpp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@ConfigurationPropertiesScan
@EnableScheduling   // periodic JWKS refresh by JarmJwksFetcher
public class TppServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(TppServiceApplication.class, args);
	}

}
