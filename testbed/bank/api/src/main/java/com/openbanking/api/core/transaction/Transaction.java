package com.openbanking.api.core.transaction;

import java.time.LocalDate;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Builder;
import lombok.Getter;

/**
 * Transaction DTO with immutable design using Builder pattern
 */
@Getter
@Builder
public class Transaction {

    private final UUID transId;
    private final LocalDate transDate;
    private final UUID accountId;
    private final UUID paymentId;
    private final Double amount;
    private final String currency;
    private final CreditOrDebit creditOrDebit;
    private final TransactionStatus status;
    private final String description;

    @JsonCreator
    public Transaction(
        @JsonProperty("transId") UUID transId, 
        @JsonProperty("transDate") LocalDate transDate, 
        @JsonProperty("accountId") UUID accountId, 
        @JsonProperty("paymentId") UUID paymentId, 
        @JsonProperty("amount") Double amount, 
        @JsonProperty("currency") String currency, 
        @JsonProperty("creditOrDebit") CreditOrDebit creditOrDebit, 
        @JsonProperty("status") TransactionStatus status, 
        @JsonProperty("description") String description) {
        this.transId = transId;
        this.transDate = transDate;
        this.accountId = accountId;
        this.paymentId = paymentId;
        this.amount = amount;
        this.currency = currency;
        this.creditOrDebit = creditOrDebit;
        this.status = status;
        this.description = description;
    }

    // Enum definitions
    public enum CreditOrDebit {
        CREDIT,
        DEBIT
    }

    public enum TransactionStatus {
        BOOKED,
        PENDING,
        REJECTED,
        COMPLETED
    }
}