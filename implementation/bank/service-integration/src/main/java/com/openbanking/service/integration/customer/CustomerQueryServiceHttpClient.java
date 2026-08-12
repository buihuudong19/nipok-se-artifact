package com.openbanking.service.integration.customer;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openbanking.api.core.customer.Customer;
import com.openbanking.api.core.customer.CustomerQueryService;
import com.openbanking.service.integration.base.BaseIntegration;

import reactor.core.publisher.Mono;

@Service
public class CustomerQueryServiceHttpClient extends BaseIntegration implements CustomerQueryService {

    private final String baseUrl;

    public CustomerQueryServiceHttpClient(ObjectMapper mapper,
                                          WebClient.Builder webClientBuilder,
                                          @Value("${app.services.customer.url:http://customer/}") String baseUrl) {
        super(mapper, webClientBuilder);
        this.baseUrl = baseUrl;
    }

    @Override
    public Mono<Customer> getCustomer(UUID customerId) {
        if (customerId == null) {
            return Mono.error(new IllegalArgumentException("Customer ID cannot be null or empty"));
        }
        String url = baseUrl + "customers/" + customerId;
        this.log.debug("Will call getCustomer API on URL: {}", url);
        return getMono(url, Customer.class);
    }
}
