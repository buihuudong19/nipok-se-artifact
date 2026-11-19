package com.openbanking.services.core.transaction.persistence;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
@Entity
@Table(name = "transactions", indexes = { @Index(name = "transactions_unique_idx", unique = true, columnList = "transId"),
    @Index(name = "idx_account_date", columnList = "accountId, transDate")
})
@Getter
@Setter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
public class TransactionEntity {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Version
    private  int version;

    @Column(nullable = false)
    private  UUID transId;
    private  LocalDate transDate;
    private  UUID accountId;
    private  UUID paymentId;
    private  BigDecimal amount;
    private  String currency;
    @Enumerated(EnumType.STRING)
    private  CreditOrDebit creditOrDebit;
    @Enumerated(EnumType.STRING)
    private  TransactionStatus status;
    private  String description;

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
