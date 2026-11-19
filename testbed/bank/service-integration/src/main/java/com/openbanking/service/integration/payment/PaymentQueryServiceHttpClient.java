package com.openbanking.service.integration.payment;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openbanking.api.core.payment.Payment;
import com.openbanking.api.core.payment.PaymentQueryService;
import com.openbanking.service.integration.base.BaseIntegration;

import reactor.core.publisher.Flux;

@Service
public class PaymentQueryServiceHttpClient extends BaseIntegration implements PaymentQueryService {

    private final String baseUrl;

    public PaymentQueryServiceHttpClient(ObjectMapper mapper,
                                         WebClient.Builder webClientBuilder,
                                         @Value("${app.services.payment.url:http://payment/}") String baseUrl) {
        super(mapper, webClientBuilder);
        this.baseUrl = baseUrl;
    }

    @Override
    public Flux<Payment> getPayments(UUID accountId) {
        if (accountId == null) {
            throw new IllegalArgumentException("Account ID cannot be null or empty");
        }
        String url = baseUrl + "accounts/" + accountId + "/payments";
        this.log.debug("Will call getPayments API on URL: {}", url);
        return getFlux(url, Payment.class);
    }
}
