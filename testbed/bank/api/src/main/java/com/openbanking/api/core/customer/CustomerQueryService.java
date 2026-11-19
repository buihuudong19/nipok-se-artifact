package com.openbanking.api.core.customer;

import java.util.UUID;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import reactor.core.publisher.Mono;

public interface CustomerQueryService {

  /**
   * Sample usage: "curl $HOST:$PORT/customers/123e4567-e89b-12d3-a456-426614174001".
   *
   * @param customerId Id of the customer
   * @return the customer, if found, else null
   */
  @GetMapping(
    value = "/customers/{customerId}",
    produces = "application/json")
  Mono<Customer> getCustomer(@PathVariable UUID customerId);

}
