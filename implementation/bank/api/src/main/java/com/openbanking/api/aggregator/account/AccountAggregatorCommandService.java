package com.openbanking.api.aggregator.account;

import java.util.UUID;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import reactor.core.publisher.Mono;


public interface AccountAggregatorCommandService {
    @Operation(
        summary = "${api.account-aggregator.create-aggregator-account.description}",
        description = "${api.account-aggregator.create-aggregator-account.notes}")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "400", description = "${api.responseCodes.badRequest.description}"),
        @ApiResponse(responseCode = "422", description = "${api.responseCodes.unprocessableEntity.description}")
    })
    @PostMapping(
        value    = "/account-aggregate",
        consumes = "application/json")
    Mono<Void> createAccount(@RequestBody AccountAggregateResponse body);

     @DeleteMapping(value = "/account-aggregate/{accountId}")
    Mono<Void> deleteAccount(@PathVariable UUID accountId);
}

