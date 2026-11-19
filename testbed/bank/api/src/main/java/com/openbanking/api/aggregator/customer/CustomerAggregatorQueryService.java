package com.openbanking.api.aggregator.customer;

import java.util.UUID;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import reactor.core.publisher.Mono;

@Tag(name = "CustomerQueryAggregator", description = "REST API for a customer information.")
public interface CustomerAggregatorQueryService {
     /**
   * Sample usage: "curl $HOST:$PORT/customer-aggregate/123e4567-e89b-12d3-a456-426614174001".
   *
   * @param customerId Id of the customer
   * @return the aggregate customer info, if found, else null
   */
  @Operation(
    summary = "${api.customer-aggregator.get-aggregator-customer.description}",
    description = "${api.customer-aggregator.get-aggregator-customer.notes}")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "${api.responseCodes.ok.description}"),
    @ApiResponse(responseCode = "400", description = "${api.responseCodes.badRequest.description}"),
    @ApiResponse(responseCode = "404", description = "${api.responseCodes.notFound.description}"),
    @ApiResponse(responseCode = "422", description = "${api.responseCodes.unprocessableEntity.description}")
  })
  @GetMapping(
    value = "/customer-aggregate/{customerId}",
    produces = "application/json")
  Mono<CustomerAggregateResponse> getCustomer(@PathVariable UUID customerId);
}
