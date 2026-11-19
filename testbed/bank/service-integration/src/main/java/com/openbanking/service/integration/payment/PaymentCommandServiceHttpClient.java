package com.openbanking.service.integration.payment;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openbanking.api.core.payment.Payment;
import com.openbanking.api.core.payment.PaymentCommandService;
import com.openbanking.service.integration.base.BaseIntegration;

import reactor.core.publisher.Mono;

@Service
public class PaymentCommandServiceHttpClient extends BaseIntegration implements PaymentCommandService {

    private final String baseUrl;

    public PaymentCommandServiceHttpClient(ObjectMapper mapper,
                                           WebClient.Builder webClientBuilder,
                                           @Value("${app.services.payment.url:http://payment/}") String baseUrl) {
        super(mapper, webClientBuilder);
        this.baseUrl = baseUrl;
    }

    @Override
    public Mono<Payment> createPayment(Payment body) {
        String url = baseUrl + "payments";
        this.log.debug("Will call createPayment API on URL: {}", url);
        return postMono(url, body, Payment.class);
    }

    @Override
    public Mono<Void> deletePayment(UUID paymentId) {
        if (paymentId == null) {
            throw new IllegalArgumentException("Payment ID cannot be null or empty");
        }
        String url = baseUrl + "payments/" + paymentId;
        this.log.debug("Will call deletePayment API on URL: {}", url);
        return deleteMono(url);
    }
}
