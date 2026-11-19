package com.openbanking.api.aggregator.customer;

import java.util.UUID;

import com.openbanking.api.core.product.Product.ProductType;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@JsonDeserialize(builder = ProductSummary.ProductSummaryBuilder.class)
public class ProductSummary {
    private final UUID productId;
    private final String productCode;
    private final String productName;
    private final ProductType productType;
    private final String description;
    private final String currency;
    private final double interestRate;

    @JsonPOJOBuilder(withPrefix = "")
    public static class ProductSummaryBuilder {
    }
}
