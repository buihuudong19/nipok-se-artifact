package com.openbanking.api.aggregator.customer;

import java.util.UUID;

import com.openbanking.api.core.payment.Payment.PaymentType;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@JsonDeserialize(builder = PaymentSummary.PaymentSummaryBuilder.class)
public class PaymentSummary {
    private final UUID paymentId;
    private final String creditorName;
    private final String creditorAccountNo;
    private final String creditorBankCode;
    private final String creditorBankName;
    private final Double amount;
    private final String currency;
    private final PaymentType paymentType;
    private final String remittanceInformation;

    @JsonPOJOBuilder(withPrefix = "")
    public static class PaymentSummaryBuilder {
    }
}
