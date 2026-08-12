package com.openbanking.api.core.payment;

import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import reactor.core.publisher.Mono;

public interface PaymentCommandService {

  @PostMapping(
    value    = "/payments",
    consumes = "application/json",
    produces = "application/json")
  Mono<Payment> createPayment(@RequestBody Payment body);

  @DeleteMapping(value = "/payments/{paymentId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  Mono<Void> deletePayment(@PathVariable UUID paymentId);
}
