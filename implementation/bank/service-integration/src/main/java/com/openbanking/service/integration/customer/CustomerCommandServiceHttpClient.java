package com.openbanking.service.integration.customer;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openbanking.api.core.customer.Customer;
import com.openbanking.api.core.customer.CustomerCommandService;
import com.openbanking.service.integration.base.BaseIntegration;

import reactor.core.publisher.Mono;

@Service
public class CustomerCommandServiceHttpClient extends BaseIntegration implements CustomerCommandService {

    private final String baseUrl;

    public CustomerCommandServiceHttpClient(ObjectMapper mapper,
                                            WebClient.Builder webClientBuilder,
                                            @Value("${app.services.customer.url:http://customer/}") String baseUrl) {
        super(mapper, webClientBuilder);
        this.baseUrl = baseUrl;
    }

    @Override
    public Mono<Customer> createCustomer(Customer body) {
        String url = baseUrl + "customers";
        this.log.debug("Will call createCustomer API on URL: {}", url);
        return postMono(url, body, Customer.class);
    }

    @Override
    public Mono<Void> deleteCustomer(UUID customerId) {
        if (customerId == null) {
            return Mono.error(new IllegalArgumentException("Customer ID cannot be null"));
        }
        String url = baseUrl + "customers/" + customerId;
        this.log.debug("Will call deleteCustomer API on URL: {}", url);
        return deleteMono(url);
    }
}
