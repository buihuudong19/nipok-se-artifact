package com.openbanking.services.agent.customer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * customer-agent — vai PSU/browser headless mô phỏng (domain Customer).
 * {@code @ConfigurationPropertiesScan} nạp {@code AgentProperties}.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class CustomerServiceApplication {

	public static void main(String[] args) {
		// MÔI TRƯỜNG ĐO: tắt hostname-verification của java.net.http (cert gateway còn SAN=localhost).
		// Phải set TRƯỚC khi HttpClient đầu tiên được tạo. Bỏ dòng này khi cert có SAN đúng domain.
		System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
		SpringApplication.run(CustomerServiceApplication.class, args);
	}
}
