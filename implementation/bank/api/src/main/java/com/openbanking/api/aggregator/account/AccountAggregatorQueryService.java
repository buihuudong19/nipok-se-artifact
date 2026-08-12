package com.openbanking.api.aggregator.account;

import java.util.UUID;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import reactor.core.publisher.Mono;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

@Tag(name = "AccountAggregator", description = "REST API for account information.")
public interface AccountAggregatorQueryService {
        /**
   * Sample usage: "curl $HOST:$PORT/account-aggregate/123e4567-e89b-12d3-a456-426614174001".
   *
   * @param accountId Id of the account
   * @return the aggregate account info, if found, else null
   */
  @Operation(
    summary = "${api.account-aggregator.get-aggregator-account.description}",
    description = "${api.account-aggregator.get-aggregator-account.notes}")
  @ApiResponses(value = {
    @ApiResponse(responseCode = "200", description = "${api.responseCodes.ok.description}"),
    @ApiResponse(responseCode = "400", description = "${api.responseCodes.badRequest.description}"),
    @ApiResponse(responseCode = "404", description = "${api.responseCodes.notFound.description}"),
    @ApiResponse(responseCode = "422", description = "${api.responseCodes.unprocessableEntity.description}")
  })
  @GetMapping(
    value = "/account-aggregate/{accountId}",
    produces = "application/json")
  Mono<AccountAggregateResponse> getAccount(@PathVariable UUID accountId);
}
