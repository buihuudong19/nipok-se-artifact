package com.openbanking.api.core.payment;

import java.time.LocalDate;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Builder;
import lombok.Getter;

/**
 * Payment class with immutable design using Builder pattern
 */
@Getter
@Builder
public class Payment {
     private final UUID paymentId;
     private final UUID debtorAccountId; //link to accountId of account service
     private final String creditorName;
     private final String creditorAccountNo;
     private final String creditorBankCode;
     private final String creditorBankName;
     private final Double amount;
     private final String currency;
     private final PaymentType paymentType;
     private final String remittanceInformation;
     private final PaymentStatus status;
     private final LocalDate executionDate;

    @JsonCreator
    public Payment(
        @JsonProperty("paymentId") UUID paymentId, 
        @JsonProperty("debtorAccountId") UUID debtorAccountId, 
        @JsonProperty("creditorName") String creditorName, 
        @JsonProperty("creditorAccountNo") String creditorAccountNo, 
        @JsonProperty("creditorBankCode") String creditorBankCode, 
        @JsonProperty("creditorBankName") String creditorBankName, 
        @JsonProperty("amount") Double amount, 
        @JsonProperty("currency") String currency, 
        @JsonProperty("paymentType") PaymentType paymentType, 
        @JsonProperty("remittanceInformation") String remittanceInformation, 
        @JsonProperty("status") PaymentStatus status, 
        @JsonProperty("executionDate") LocalDate executionDate) {
        this.paymentId = paymentId;
        this.debtorAccountId = debtorAccountId;
        this.creditorName = creditorName;
        this.creditorAccountNo = creditorAccountNo;
        this.creditorBankCode = creditorBankCode;
        this.creditorBankName = creditorBankName;
        this.amount = amount;
        this.currency = currency;
        this.paymentType = paymentType;
        this.remittanceInformation = remittanceInformation;
        this.status = status;
        this.executionDate = executionDate;
    }

    public enum PaymentStatus {
        PENDING,
        ACCEPTED,
        REJECTED,
        EXECUTED,
        CANCELLED
    }
    public enum PaymentType {
        DOMESTIC,
        INTERNATIONAL,
        SEPA,
        INSTANT,
        SWIFT
    }
}
