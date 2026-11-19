package com.openbanking.api.core.customer;

import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import reactor.core.publisher.Mono;

public interface CustomerCommandService {

  /**
   * @param body A JSON representation of the new customer
   * @return A JSON representation of the newly created customer
   */
  @PostMapping(
    value    = "/customers",
    consumes = "application/json",
    produces = "application/json")
  Mono<Customer> createCustomer(@RequestBody Customer body);

  /**
   * Sample usage: "curl -X DELETE $HOST:$PORT/customers/{customerId}".
   *
   * @param customerId Id of the customer
   */
  @DeleteMapping(value = "/customers/{customerId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  Mono<Void> deleteCustomer(@PathVariable UUID customerId);

}
