package com.openbanking.services.core.product.persistence;

import java.util.UUID;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Document(collection = "products")
@Getter
@Setter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
public class ProductEntity {
    @Id
    private  String id;
    @Version 
    private  Integer version;
    @Indexed(unique = true)
    private  UUID productId;
    private  String productCode;
    private  String productName;
    private  ProductType productType;
    private  String description;
    private  String currency;
    private  double interestRate;
    private  ProductStatus status;

    
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
