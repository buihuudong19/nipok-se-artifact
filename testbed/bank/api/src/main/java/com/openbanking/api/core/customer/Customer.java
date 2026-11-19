package com.openbanking.api.core.customer;

import java.time.LocalDate;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;

@Getter
public class Customer {

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

    private String serviceAddress;

    public void setServiceAddress(String serviceAddress) {
        this.serviceAddress = serviceAddress;
    }

    @JsonCreator
    public Customer(
        @JsonProperty("customerId") UUID customerId, 
        @JsonProperty("customerName") String customerName, 
        @JsonProperty("dob") LocalDate dob, 
        @JsonProperty("address") String address, 
        @JsonProperty("email") String email, 
        @JsonProperty("phoneNum") String phoneNum, 
        @JsonProperty("identityId") String identityId, 
        @JsonProperty("customerType") CustomerType customerType, 
        @JsonProperty("kycStatus") KycStatus kycStatus, 
        @JsonProperty("kycVerifiedAt") LocalDate kycVerifiedAt, 
        @JsonProperty("riskRate") RiskRate riskRate,
        @JsonProperty("serviceAddress") String serviceAddress
    ) {
        this.customerId = customerId;
        this.customerName = customerName;
        this.dob = dob;
        this.address = address;
        this.email = email;
        this.phoneNum = phoneNum;
        this.identityId = identityId;
        this.customerType = customerType;
        this.kycStatus = kycStatus;
        this.kycVerifiedAt = kycVerifiedAt;
        this.riskRate = riskRate;
        this.serviceAddress = serviceAddress;
    }

    

    // Enum definitions
    public enum CustomerType {
        INDIVIDUAL,
        BUSINESS,
        CORPORATE
    }

    public enum KycStatus {
        PENDING,
        VERIFIED,
        REJECTED,
        EXPIRED
    }

    public enum RiskRate {
        LOW,
        MEDIUM,
        HIGH
    }
}