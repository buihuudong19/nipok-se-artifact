package com.openbanking.services.aggregator.account.services;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.web.bind.annotation.RestController;

import com.openbanking.api.aggregator.account.AccountAggregateResponse;
import com.openbanking.api.aggregator.account.AccountAggregatorQueryService;
import com.openbanking.api.aggregator.account.AccountSummary;
import com.openbanking.api.aggregator.customer.PaymentSummary;
import com.openbanking.api.aggregator.customer.ProductSummary;
import com.openbanking.api.aggregator.customer.TransactionSummary;
import com.openbanking.api.core.account.Account;
import com.openbanking.api.core.account.AccountQueryService;
import com.openbanking.api.core.payment.PaymentQueryService;
import com.openbanking.api.core.product.Product;
import com.openbanking.api.core.product.ProductQueryService;
import com.openbanking.api.core.transaction.TransactionQueryService;
import com.openbanking.api.exceptions.NotFoundException;
import com.openbanking.services.aggregator.account.ConsentStatusClient;
import com.openbanking.services.aggregator.account.RarClaims;

import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.server.ResponseStatusException;

import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@RestController
public class AccountAggregatorQueryServiceImpl implements AccountAggregatorQueryService {
    private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT"); // STRIDE R
    private final AccountQueryService accountService;
    private final ProductQueryService productService;
    private final TransactionQueryService transactionService;
    private final PaymentQueryService paymentService;
    private final ConsentStatusClient consentStatus;

    public AccountAggregatorQueryServiceImpl(AccountQueryService accountService, ProductQueryService productService, TransactionQueryService transactionService, PaymentQueryService paymentService, ConsentStatusClient consentStatus) {
        this.accountService = accountService;
        this.productService = productService;
        this.transactionService = transactionService;
        this.paymentService = paymentService;
        this.consentStatus = consentStatus;
    }

    @Override
    public Mono<AccountAggregateResponse> getAccount(UUID accountId) {
        // RAR (RFC 9396) for accounts + revocation check: enforced in the service layer because it needs
        // account.customerId (known only AFTER the fetch). No JWT/no RAR -> fetched as before (backward compatibility).
        return ReactiveSecurityContextHolder.getContext()
            .map(SecurityContext::getAuthentication)
            .filter(JwtAuthenticationToken.class::isInstance)
            .map(a -> ((JwtAuthenticationToken) a).getToken())
            .flatMap(jwt -> enforceAndFetch(accountId, jwt))
            .switchIfEmpty(Mono.defer(() -> fetchAccount(accountId).flatMap(this::buildAccountAggregateResponse)));
    }

    private Mono<Account> fetchAccount(UUID accountId) {
        return Mono.fromCallable(() -> {
            Account account = accountService.getAccount(accountId);
            if (account == null) {
                throw new NotFoundException("No account found for accountId: " + accountId);
            }
            return account;
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /** Revocation-check (consent active) -> fetch -> ownership-check (account.customerId ∈ consent customers). */
    private Mono<AccountAggregateResponse> enforceAndFetch(UUID accountId, Jwt jwt) {
        Set<String> allowed = RarClaims.allowedCustomerIds(jwt);   // null = token without RAR
        String consentId = RarClaims.consentId(jwt);
        return consentStatus.isActive(consentId).flatMap(active -> {
            if (Boolean.FALSE.equals(active)) {
                AUDIT.warn("{\"event\":\"BOLA_DENY\",\"reason\":\"consent_revoked\",\"resource\":\"account\","
                    + "\"sub\":\"{}\",\"consent_id\":\"{}\",\"account_id\":\"{}\"}",
                    jwt.getSubject(), mask(consentId), mask(accountId.toString()));
                return Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN, "consent revoked"));
            }
            return fetchAccount(accountId).flatMap(account -> {
                String owner = account.getCustomerId() == null ? null : account.getCustomerId().toString();
                if (allowed != null && owner != null && !allowed.contains(owner)) {
                    AUDIT.warn("{\"event\":\"BOLA_DENY\",\"reason\":\"account_owner_not_in_consent\",\"resource\":\"account\","
                        + "\"sub\":\"{}\",\"consent_id\":\"{}\",\"account_id\":\"{}\",\"owner\":\"{}\"}",
                        jwt.getSubject(), mask(consentId), mask(accountId.toString()), mask(owner));
                    return Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN,
                        "account not among the resources of the consent (resource binding)"));
                }
                return buildAccountAggregateResponse(account);
            });
        });
    }

    private static String mask(String s) {
        if (s == null || s.length() < 12) {
            return s;
        }
        return s.substring(0, 4) + "***" + s.substring(s.length() - 4);
    }

    private Mono<AccountAggregateResponse> buildAccountAggregateResponse(Account account) {
        AccountSummary accountSummary = AccountSummary.builder()
                .accountId(account.getAccountId())
                .customerId(account.getCustomerId())
                .accountNo(account.getAccountNo())
                .currency(account.getCurrency())
                .accountType(account.getAccountType())
                .nickname(account.getNickname())
                .status(account.getStatus())
                .openingDate(account.getOpeningDate())
                .balance(account.getBalance())
                .build();

        // Step 2: product (MongoDB), transactions (MSSQL), payments (MySQL) - independent, run in parallel
        Mono<ProductSummary> productMono = Mono.fromCallable(() -> {
            Product product = productService.getProduct(account.getProductId());
            return ProductSummary.builder()
                    .productId(product.getProductId())
                    .productName(product.getProductName())
                    .productType(product.getProductType())
                    .build();
        }).subscribeOn(Schedulers.boundedElastic());

        Mono<List<TransactionSummary>> transactionsMono = Mono.fromCallable(() ->
            transactionService.getTransactions(account.getAccountId()).stream()
                .map(tx -> TransactionSummary.builder()
                    .transId(tx.getTransId())
                    .transDate(tx.getTransDate())
                    .amount(tx.getAmount())
                    .currency(tx.getCurrency())
                    .creditOrDebit(tx.getCreditOrDebit())
                    .description(tx.getDescription())
                    .build())
                .collect(Collectors.toList())
        ).subscribeOn(Schedulers.boundedElastic());

        Mono<List<PaymentSummary>> paymentsMono = paymentService.getPayments(account.getAccountId())
            .map(payment -> PaymentSummary.builder()
                .paymentId(payment.getPaymentId())
                .creditorName(payment.getCreditorName())
                .creditorAccountNo(payment.getCreditorAccountNo())
                .creditorBankCode(payment.getCreditorBankCode())
                .creditorBankName(payment.getCreditorBankName())
                .amount(payment.getAmount())
                .currency(payment.getCurrency())
                .paymentType(payment.getPaymentType())
                .remittanceInformation(payment.getRemittanceInformation())
                .build())
            .collectList();

        return Mono.zip(productMono, transactionsMono, paymentsMono)
                .map(tuple -> AccountAggregateResponse.builder()
                        .accountSummary(accountSummary)
                        .productSummary(tuple.getT1())
                        .transactions(tuple.getT2())
                        .payments(tuple.getT3())
                        .build());
    }
}
