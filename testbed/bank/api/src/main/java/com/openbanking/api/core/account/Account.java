package com.openbanking.api.core.account;

import java.time.LocalDate;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Builder;
import lombok.Getter;

/**
 * Account class with immutable design using Builder pattern
 */
@Getter
@Builder
public class Account {
    private final UUID accountId;
    private final UUID customerId;
    private final UUID productId;
    private final String accountNo; 
    private final String currency;
    private final AccountType accountType;
    private final String nickname;
    private final AccountStatus status;
    private final LocalDate openingDate;
    private final Double balance;

    @JsonCreator
    public Account(
        @JsonProperty("accountId") UUID accountId, 
        @JsonProperty("customerId") UUID customerId, 
        @JsonProperty("productId") UUID productId, 
        @JsonProperty("accountNo") String accountNo, 
        @JsonProperty("currency") String currency, 
        @JsonProperty("accountType") AccountType accountType, 
        @JsonProperty("nickname") String nickname, 
        @JsonProperty("status") AccountStatus status, 
        @JsonProperty("openingDate") LocalDate openingDate, 
        @JsonProperty("balance") Double balance) {
        this.accountId = accountId;
        this.customerId = customerId;
        this.productId = productId;
        this.accountNo = accountNo;
        this.currency = currency;
        this.accountType = accountType;
        this.nickname = nickname;
        this.status = status;
        this.openingDate = openingDate;
        this.balance = balance;
    }

    // Enum definitions
    public enum AccountType {
        CURRENT,
        SAVINGS,
        TERM_DEPOSIT,
        LOAN
    }

    public enum AccountStatus {
        ENABLED,
        BLOCKED,
        DORMANT,
        CLOSED
    }
}