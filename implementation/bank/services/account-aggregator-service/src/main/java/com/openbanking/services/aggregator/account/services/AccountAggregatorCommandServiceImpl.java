package com.openbanking.services.aggregator.account.services;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RestController;

import com.openbanking.api.aggregator.account.AccountAggregateResponse;
import com.openbanking.api.aggregator.account.AccountAggregatorCommandService;
import com.openbanking.api.aggregator.account.AccountSummary;
import com.openbanking.api.aggregator.customer.ProductSummary;
import com.openbanking.api.core.account.Account;
import com.openbanking.api.core.account.AccountCommandService;
import com.openbanking.api.core.payment.Payment;
import com.openbanking.api.core.payment.PaymentCommandService;
import com.openbanking.api.core.payment.PaymentQueryService;
import com.openbanking.api.core.product.Product;
import com.openbanking.api.core.product.ProductCommandService;
import com.openbanking.api.core.product.ProductQueryService;
import com.openbanking.api.core.transaction.Transaction;
import com.openbanking.api.core.transaction.TransactionCommandService;
import com.openbanking.api.core.transaction.TransactionQueryService;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@RestController
public class AccountAggregatorCommandServiceImpl implements AccountAggregatorCommandService {
    private static final Logger LOG = LoggerFactory.getLogger(AccountAggregatorCommandServiceImpl.class);

    private final ProductCommandService productCommandService;
    private final ProductQueryService productQueryService;
    private final AccountCommandService accountCommandService;
    private final PaymentCommandService paymentCommandService;
    private final PaymentQueryService paymentQueryService;
    private final TransactionCommandService transactionCommandService;
    private final TransactionQueryService transactionQueryService;

    public AccountAggregatorCommandServiceImpl(
            ProductCommandService productCommandService,
            ProductQueryService productQueryService,
            AccountCommandService accountCommandService,
            PaymentCommandService paymentCommandService,
            PaymentQueryService paymentQueryService,
            TransactionCommandService transactionCommandService,
            TransactionQueryService transactionQueryService) {
        this.productCommandService = productCommandService;
        this.productQueryService = productQueryService;
        this.accountCommandService = accountCommandService;
        this.paymentCommandService = paymentCommandService;
        this.paymentQueryService = paymentQueryService;
        this.transactionCommandService = transactionCommandService;
        this.transactionQueryService = transactionQueryService;
    }

    private boolean productExists(UUID productId) {
        try {
            return this.productQueryService.getProduct(productId) != null;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public Mono<Void> createAccount(AccountAggregateResponse body) {
        LOG.debug("createAggregatorAccount: Creates an account aggregate");
        AccountSummary as = body.getAccountSummary();
        ProductSummary ps = body.getProductSummary();

        // Step 1: create product if not exists (MongoDB) — must precede account creation
        Mono<Void> createProductStep = Mono.<Void>fromRunnable(() -> {
            if (!productExists(ps.getProductId())) {
                productCommandService.createProduct(new Product(
                    ps.getProductId(), ps.getProductCode(), ps.getProductName(),
                    ps.getProductType(), ps.getDescription(), ps.getCurrency(),
                    ps.getInterestRate(), null, null));
            }
        }).subscribeOn(Schedulers.boundedElastic());

        // Step 2: create account (PostgreSQL) — after product
        Mono<Void> createAccountStep = Mono.<Void>fromRunnable(() ->
            accountCommandService.createAccount(new Account(
                as.getAccountId(), as.getCustomerId(), ps.getProductId(),
                as.getAccountNo(), as.getCurrency(), as.getAccountType(),
                as.getNickname(), as.getStatus(), as.getOpeningDate(), as.getBalance()))
        ).subscribeOn(Schedulers.boundedElastic());

        // Step 3: payments (MySQL) and transactions (MSSQL) — independent, run in parallel
        Mono<Void> createPaymentsMono = Flux.fromIterable(body.getPayments())
            .flatMap(paymentSummary -> Mono.<Void>fromRunnable(() ->
                paymentCommandService.createPayment(new Payment(
                    paymentSummary.getPaymentId(), as.getAccountId(),
                    paymentSummary.getCreditorName(), paymentSummary.getCreditorAccountNo(),
                    paymentSummary.getCreditorBankCode(), paymentSummary.getCreditorBankName(),
                    paymentSummary.getAmount(), paymentSummary.getCurrency(),
                    paymentSummary.getPaymentType(), paymentSummary.getRemittanceInformation(),
                    null, null)))
                .subscribeOn(Schedulers.boundedElastic()))
            .then();

        Mono<Void> createTransactionsMono = Flux.fromIterable(body.getTransactions())
            .flatMap(transactionSummary -> Mono.<Void>fromRunnable(() ->
                transactionCommandService.createTransaction(new Transaction(
                    transactionSummary.getTransId(), transactionSummary.getTransDate(),
                    as.getAccountId(), null,
                    transactionSummary.getAmount(), transactionSummary.getCurrency(),
                    transactionSummary.getCreditOrDebit(), null,
                    transactionSummary.getDescription())))
                .subscribeOn(Schedulers.boundedElastic()))
            .then();

        return createProductStep
            .then(createAccountStep)
            .then(Mono.when(createPaymentsMono, createTransactionsMono))
            .doOnSuccess(v -> LOG.debug("createAggregatorAccount: account aggregate created for accountId: {}", as.getAccountId()));
    }

    @Override
    public Mono<Void> deleteAccount(UUID accountId) {
        LOG.debug("deleteAggregatorAccount: Deletes an account aggregate for accountId: {}", accountId);

        // fetch and delete transactions (MSSQL) in parallel with payments (MySQL)
        Mono<Void> deleteTransactionsMono = Mono.fromCallable(() -> transactionQueryService.getTransactions(accountId))
            .subscribeOn(Schedulers.boundedElastic())
            .flatMap(transactions ->
                Flux.fromIterable(transactions)
                    .flatMap(tx -> Mono.<Void>fromRunnable(() ->
                        transactionCommandService.deleteTransaction(tx.getTransId()))
                        .subscribeOn(Schedulers.boundedElastic()))
                    .then()
            );

        Mono<Void> deletePaymentsMono = paymentQueryService.getPayments(accountId)
            .flatMap(payment -> paymentCommandService.deletePayment(payment.getPaymentId()))
            .then();

        // after all transactions and payments deleted: delete account (PostgreSQL)
        return Mono.when(deleteTransactionsMono, deletePaymentsMono)
            .then(Mono.<Void>fromRunnable(() -> {
                accountCommandService.deleteAccount(accountId);
                LOG.debug("deleteAggregatorAccount: aggregate entities deleted for accountId: {}", accountId);
            }).subscribeOn(Schedulers.boundedElastic()));
    }
}
