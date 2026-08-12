package com.openbanking.services.core.payment.persistence;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.UUID;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Table("payments")
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class PaymentEntity {
    @Id
    private Long id;
    @Version
    private int version;

    private UUID paymentId;
    private UUID debtorAccountId;
    private String creditorName;
    private String creditorAccountNo;
    private String creditorBankCode;
    private String creditorBankName;
    private BigDecimal amount;
    private String currency;
    private PaymentType paymentType;
    private String remittanceInformation;
    private PaymentStatus status;
    private LocalDate executionDate;

    public enum PaymentStatus {
        PENDING, ACCEPTED, REJECTED, EXECUTED, CANCELLED
    }

    public enum PaymentType {
        DOMESTIC, INTERNATIONAL, SEPA, INSTANT, SWIFT
    }
}
