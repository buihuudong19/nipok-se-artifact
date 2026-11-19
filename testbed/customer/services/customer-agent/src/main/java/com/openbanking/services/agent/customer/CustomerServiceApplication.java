package com.openbanking.services.agent.customer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * customer-agent - simulated PSU/headless browser (customer domain).
 * {@code @ConfigurationPropertiesScan} loads {@code AgentProperties}.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class CustomerServiceApplication {

	public static void main(String[] args) {
		// MEASUREMENT ENVIRONMENT: hostname verification of java.net.http disabled (the gateway certificate still has SAN=localhost).
		// Must be set BEFORE the first HttpClient is created. Remove this line when the certificate has the right SAN.
		System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
		SpringApplication.run(CustomerServiceApplication.class, args);
	}
}
