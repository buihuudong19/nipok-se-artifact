package com.openbanking.api.aggregator.customer;

import java.util.List;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@JsonDeserialize(builder = CustomerAggregateResponse.CustomerAggregateResponseBuilder.class)
public class CustomerAggregateResponse {
    private final CustomerSummary customerSummary;
    private final List<AccountAggregateSummary> accounts;

    @JsonPOJOBuilder(withPrefix = "")
    public static class CustomerAggregateResponseBuilder {
    }
}