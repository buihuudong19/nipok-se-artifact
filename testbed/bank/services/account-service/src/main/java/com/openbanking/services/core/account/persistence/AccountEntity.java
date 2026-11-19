package com.openbanking.services.core.account.persistence;

import java.time.LocalDate;
import java.util.UUID;

import jakarta.persistence.Entity;
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
@Table(name = "accounts", indexes = { @Index(name = "accounts_unique_idx", unique = true, columnList = "accountId, customerId") })
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class AccountEntity {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Version
    private  int version;
  
    private  UUID accountId;
    private  UUID customerId;
    private  UUID productId;
    private  String accountNo; 
    private  String currency;
    private  AccountType accountType;
    private  String nickname;
    private  AccountStatus status;
    private  LocalDate openingDate;
    private  Double balance;

    // Enum definitions
    public enum AccountType {
        CURRENT,
        SAVINGS,
        TERM_DEPOSIT,
        LOAN
    }

    public enum AccountStatus {
        ENABLED,
        BLOCKED,
        DORMANT,
        CLOSED
    }
}
