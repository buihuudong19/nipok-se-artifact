package com.openbanking.api.aggregator.customer;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

import com.openbanking.api.core.account.Account.AccountStatus;
import com.openbanking.api.core.account.Account.AccountType;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@JsonDeserialize(builder = AccountAggregateSummary.AccountAggregateSummaryBuilder.class)
public class AccountAggregateSummary {
    private final UUID accountId;
    private final String accountNo;
    private final String currency;
    private final AccountType accountType;
    private final AccountStatus status;
    private final LocalDate openingDate;
    private final Double balance;
    private final ProductSummary product;
    private final List<PaymentSummary> payments;
    private final List<TransactionSummary> transactions;

    @JsonPOJOBuilder(withPrefix = "")
    public static class AccountAggregateSummaryBuilder {
    }
}
