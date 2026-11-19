package com.openbanking.api.aggregator.account;
import java.util.List;

import com.openbanking.api.aggregator.customer.PaymentSummary;
import com.openbanking.api.aggregator.customer.ProductSummary;
import com.openbanking.api.aggregator.customer.TransactionSummary;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@JsonDeserialize(builder = AccountAggregateResponse.AccountAggregateResponseBuilder.class)
public class AccountAggregateResponse {
    private final AccountSummary accountSummary;
    private final ProductSummary productSummary;
    private final List<TransactionSummary> transactions;
    private final List<PaymentSummary> payments;

    @JsonPOJOBuilder(withPrefix = "")
    public static class AccountAggregateResponseBuilder {
    }
}
