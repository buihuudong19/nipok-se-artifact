package com.openbanking.api.aggregator.customer;
import java.util.UUID;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import reactor.core.publisher.Mono;

@Tag(name = "CustomerCommandAggregator", description = "REST API for a customer information.")
public interface CustomerAggregatorCommandService {
    /**
     * Sample usage, see below.
     *
     * curl -X POST $HOST:$PORT/customer-aggregate\
     *   -H "Content-Type: application/json" --data \
     *   '<Json of a the customer>'
     *
     * @param body A JSON representation of the new aggregator product
     */
    @Operation(
        summary = "${api.customer-aggregator.create-aggregator-customer.description}",
        description = "${api.customer-aggregator.create-aggregator-customer.notes}")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "400", description = "${api.responseCodes.badRequest.description}"),
        @ApiResponse(responseCode = "422", description = "${api.responseCodes.unprocessableEntity.description}")
    })
    @PostMapping(
        value    = "/customer-aggregate",
        consumes = "application/json")
    Mono<Void> createCustomer(@RequestBody CustomerAggregateResponse body);

    /**
     * Sample usage: "curl -X DELETE $HOST:$PORT/customer-aggregate/{customerId}".
     *
     * @param customerId Id of the customer
     */
    @Operation(
        summary = "${api.customer-aggregator.delete-aggregator-customer.description}",
        description = "${api.customer-aggregator.delete-aggregator-customer.notes}")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "400", description = "${api.responseCodes.badRequest.description}"),
        @ApiResponse(responseCode = "422", description = "${api.responseCodes.unprocessableEntity.description}")
    })
    @DeleteMapping(value = "/customer-aggregate/{customerId}")
    Mono<Void> deleteCustomer(@PathVariable UUID customerId);
}
