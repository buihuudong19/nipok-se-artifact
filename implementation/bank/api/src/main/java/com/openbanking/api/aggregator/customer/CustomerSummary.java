package com.openbanking.api.aggregator.customer;

import java.time.LocalDate;
import java.util.UUID;

import com.openbanking.api.core.customer.Customer.CustomerType;
import com.openbanking.api.core.customer.Customer.KycStatus;
import com.openbanking.api.core.customer.Customer.RiskRate;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@JsonDeserialize(builder = CustomerSummary.CustomerSummaryBuilder.class)
public class CustomerSummary {
    private final UUID customerId;
    private final String customerName;
    private final LocalDate dob;
    private final String address;
    private final String email;
    private final String phoneNum;
    private final String identityId;
    private final CustomerType customerType;
    private final KycStatus kycStatus;
    private final LocalDate kycVerifiedAt;
    private final RiskRate riskRate;

    @JsonPOJOBuilder(withPrefix = "")
    public static class CustomerSummaryBuilder {
    }
}
