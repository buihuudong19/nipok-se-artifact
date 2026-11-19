package com.openbanking.api.core.product;

import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;

@Getter
public class Product {

    private final UUID productId;
    private final String productCode;
    private final String productName;
    private final ProductType productType;
    private final String description;
    private final String currency;
    private final double interestRate;
    private final ProductStatus status;

    private String serviceAddress;

    public void setServiceAddress(String serviceAddress) {
        this.serviceAddress = serviceAddress;
    }

    @JsonCreator
    public Product(
        @JsonProperty("productId") UUID productId, 
        @JsonProperty("productCode") String productCode, 
        @JsonProperty("productName") String productName, 
        @JsonProperty("productType") ProductType productType, 
        @JsonProperty("description") String description, 
        @JsonProperty("currency") String currency, 
        @JsonProperty("interestRate") double interestRate, 
        @JsonProperty("status") ProductStatus status,
        @JsonProperty("serviceAddress") String serviceAddress
        
    ) {
        this.productId = productId;
        this.productCode = productCode;
        this.productName = productName;
        this.productType = productType;
        this.description = description;
        this.currency = currency;
        this.interestRate = interestRate;
        this.status = status;
        this.serviceAddress = serviceAddress;
    }
 
    public enum ProductType {
        ACCOUNT,
        CARD,
        LOAN,
        DEPOSIT,
        INVESTMENT
    }

     public enum ProductStatus {
        ACTIVE,
        INACTIVE,
        DISCONTINUED
    }

}
