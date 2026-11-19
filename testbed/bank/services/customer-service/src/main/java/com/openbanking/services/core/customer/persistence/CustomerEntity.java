package com.openbanking.services.core.customer.persistence;

import java.time.LocalDate;
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

@Document(collection = "customers")
@Getter
@Setter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
public class CustomerEntity {
    @Id
    private String id;
    @Version 
    private  Integer version;
    
    @Indexed(unique = true)
    private  UUID customerId;
    private  String customerName;
    private  LocalDate dob;
    private  String address;      
    private  String email;
    private  String phoneNum;
    private  String identityId;
    
    private  CustomerType customerType;  
    private  KycStatus kycStatus;
    private  LocalDate kycVerifiedAt;
    private  RiskRate riskRate;

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
