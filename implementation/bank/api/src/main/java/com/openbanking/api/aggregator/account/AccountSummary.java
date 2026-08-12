package com.openbanking.api.aggregator.account;

import java.time.LocalDate;
import java.util.UUID;

import com.openbanking.api.core.account.Account.AccountStatus;
import com.openbanking.api.core.account.Account.AccountType;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@JsonDeserialize(builder = AccountSummary.AccountSummaryBuilder.class)
public class AccountSummary {
    private final UUID accountId;
    private final UUID customerId;
    private final String accountNo;
    private final String currency;
    private final AccountType accountType;
    private final String nickname;
    private final AccountStatus status;
    private final LocalDate openingDate;
    private final Double balance;

    @JsonPOJOBuilder(withPrefix = "")
    public static class AccountSummaryBuilder {
    }
}
