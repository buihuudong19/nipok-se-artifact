package com.openbanking.api.core.payment;

import java.util.UUID;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import reactor.core.publisher.Flux;

public interface PaymentQueryService {

  @GetMapping(
    value = "/accounts/{accountId}/payments",
    produces = "application/json")
  Flux<Payment> getPayments(@PathVariable UUID accountId);
}
