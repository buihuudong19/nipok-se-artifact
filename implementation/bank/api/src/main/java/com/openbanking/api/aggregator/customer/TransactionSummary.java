package com.openbanking.api.aggregator.customer;

import java.time.LocalDate;
import java.util.UUID;

import com.openbanking.api.core.transaction.Transaction.CreditOrDebit;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@JsonDeserialize(builder = TransactionSummary.TransactionSummaryBuilder.class)
public class TransactionSummary {
    private final UUID transId;
    private final LocalDate transDate;
    private final Double amount;
    private final String currency;
    private final CreditOrDebit creditOrDebit;
    private final String description;

    @JsonPOJOBuilder(withPrefix = "")
    public static class TransactionSummaryBuilder {
    }
}
