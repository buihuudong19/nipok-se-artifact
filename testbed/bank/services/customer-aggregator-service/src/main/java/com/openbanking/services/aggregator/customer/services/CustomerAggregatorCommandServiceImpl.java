package com.openbanking.services.aggregator.customer.services;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RestController;

import com.openbanking.api.aggregator.customer.AccountAggregateSummary;
import com.openbanking.api.aggregator.customer.CustomerAggregateResponse;
import com.openbanking.api.aggregator.customer.CustomerAggregatorCommandService;
import com.openbanking.api.aggregator.customer.CustomerSummary;
import com.openbanking.api.aggregator.customer.ProductSummary;
import com.openbanking.api.core.account.Account;
import com.openbanking.api.core.account.AccountCommandService;
import com.openbanking.api.core.account.AccountQueryService;
import com.openbanking.api.core.customer.Customer;
import com.openbanking.api.core.customer.CustomerCommandService;
import com.openbanking.api.core.customer.CustomerQueryService;
import com.openbanking.api.core.payment.Payment;
import com.openbanking.api.core.payment.PaymentCommandService;
import com.openbanking.api.core.payment.PaymentQueryService;
import com.openbanking.api.core.product.Product;
import com.openbanking.api.core.product.ProductCommandService;
import com.openbanking.api.core.transaction.Transaction;
import com.openbanking.api.core.transaction.TransactionCommandService;
import com.openbanking.api.core.transaction.TransactionQueryService;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@RestController
public class CustomerAggregatorCommandServiceImpl implements CustomerAggregatorCommandService {
    private static final Logger LOG = LoggerFactory.getLogger(CustomerAggregatorCommandServiceImpl.class);
    private final CustomerCommandService customerCommandService;
    private final CustomerQueryService customerQueryService;
    private final ProductCommandService productCommandService;
    private final AccountCommandService accountCommandService;
    private final AccountQueryService accountQueryService;
    private final PaymentCommandService paymentCommandService;
    private final PaymentQueryService paymentQueryService;
    private final TransactionCommandService transactionCommandService;
    private final TransactionQueryService transactionQueryService;

    public CustomerAggregatorCommandServiceImpl(
            CustomerCommandService customerCommandService,
            CustomerQueryService customerQueryService,
            ProductCommandService productCommandService,
            AccountCommandService accountCommandService,
            AccountQueryService accountQueryService,
            PaymentCommandService paymentCommandService,
            PaymentQueryService paymentQueryService,
            TransactionCommandService transactionCommandService,
            TransactionQueryService transactionQueryService) {
        this.customerCommandService = customerCommandService;
        this.customerQueryService = customerQueryService;
        this.productCommandService = productCommandService;
        this.accountCommandService = accountCommandService;
        this.accountQueryService = accountQueryService;
        this.paymentCommandService = paymentCommandService;
        this.paymentQueryService = paymentQueryService;
        this.transactionCommandService = transactionCommandService;
        this.transactionQueryService = transactionQueryService;
    }

    private Mono<Boolean> customerExists(UUID customerId) {
        return customerQueryService.getCustomer(customerId)
            .map(c -> true)
            .onErrorReturn(false)
            .defaultIfEmpty(false);
    }

    private boolean accountExists(UUID accountId) {
        try {
            return this.accountQueryService.getAccount(accountId) != null;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public Mono<Void> createCustomer(CustomerAggregateResponse body) {
        CustomerSummary cs = body.getCustomerSummary();

        // Step 1: check & create customer reactively (customerQueryService now returns Mono<Customer>)
        Mono<Void> createCustomerStep = customerExists(cs.getCustomerId())
            .flatMap(exists -> {
                if (exists) return Mono.<Void>empty();
                return customerCommandService.createCustomer(new Customer(
                    cs.getCustomerId(), cs.getCustomerName(), cs.getDob(), cs.getAddress(),
                    cs.getEmail(), cs.getPhoneNum(), cs.getIdentityId(), cs.getCustomerType(),
                    cs.getKycStatus(), cs.getKycVerifiedAt(), cs.getRiskRate(), null)).then();
            });

        // Step 2: process all accounts in parallel (each account is independent)
        return createCustomerStep.then(
            Flux.fromIterable(body.getAccounts())
                .flatMap(accountSummary -> createAccountAggregate(accountSummary, cs.getCustomerId()))
                .then()
        );
    }

    private Mono<Void> createAccountAggregate(AccountAggregateSummary accountSummary, UUID customerId) {
        return Mono.fromCallable(() -> accountExists(accountSummary.getAccountId()))
            .subscribeOn(Schedulers.boundedElastic())
            .flatMap(exists -> {
                if (exists) return Mono.<Void>empty();

                ProductSummary ps = accountSummary.getProduct();

                // product must be created before account (sequential within each account)
                Mono<Void> createProductThenAccount = Mono.<Void>fromRunnable(() -> {
                    productCommandService.createProduct(new Product(
                        ps.getProductId(), ps.getProductCode(), ps.getProductName(),
                        ps.getProductType(), ps.getDescription(), ps.getCurrency(),
                        ps.getInterestRate(), null, null));
                    accountCommandService.createAccount(new Account(
                        accountSummary.getAccountId(), customerId, ps.getProductId(),
                        accountSummary.getAccountNo(), accountSummary.getCurrency(),
                        accountSummary.getAccountType(), null,
                        accountSummary.getStatus(), accountSummary.getOpeningDate(),
                        accountSummary.getBalance()));
                }).subscribeOn(Schedulers.boundedElastic());

                // after account exists: payments (MySQL) and transactions (MSSQL) are independent
                return createProductThenAccount.then(
                    Mono.when(
                        createPayments(accountSummary),
                        createTransactions(accountSummary)
                    )
                );
            });
    }

    private Mono<Void> createPayments(AccountAggregateSummary accountSummary) {
        return Flux.fromIterable(accountSummary.getPayments())
            .<Void>flatMap(ps -> paymentCommandService.createPayment(new Payment(
                    ps.getPaymentId(), accountSummary.getAccountId(),
                    ps.getCreditorName(), ps.getCreditorAccountNo(),
                    ps.getCreditorBankCode(), ps.getCreditorBankName(),
                    ps.getAmount(), ps.getCurrency(),
                    ps.getPaymentType(), ps.getRemittanceInformation(),
                    null, null))
                .then())
            .then();
    }

    private Mono<Void> createTransactions(AccountAggregateSummary accountSummary) {
        return Flux.fromIterable(accountSummary.getTransactions())
            .flatMap(ts -> Mono.<Void>fromRunnable(() ->
                transactionCommandService.createTransaction(new Transaction(
                    ts.getTransId(), ts.getTransDate(),
                    accountSummary.getAccountId(), null,
                    ts.getAmount(), ts.getCurrency(),
                    ts.getCreditOrDebit(), null,
                    ts.getDescription())))
                .subscribeOn(Schedulers.boundedElastic()))
            .then();
    }

    @Override
    public Mono<Void> deleteCustomer(UUID customerId) {
        LOG.debug("deleteAggregatorCustomer: Deletes a customer aggregate for customerId: {}", customerId);

        // Step 1: delete all accounts in parallel, then delete customer last
        return Mono.fromCallable(() -> accountQueryService.getAccounts(customerId))
            .subscribeOn(Schedulers.boundedElastic())
            .flatMap(accounts ->
                Flux.fromIterable(accounts)
                    .flatMap(this::deleteAccountAggregate)
                    .then()
            )
            .then(customerCommandService.deleteCustomer(customerId))
            .doOnSuccess(v -> LOG.debug("deleteAggregatorCustomer: aggregate entities deleted for customerId: {}", customerId));
    }

    private Mono<Void> deleteAccountAggregate(Account account) {
        UUID accountId = account.getAccountId();

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

        // after all transactions and payments are gone: delete account (PostgreSQL) and product (MongoDB) in parallel
        return Mono.when(deleteTransactionsMono, deletePaymentsMono)
            .then(
                Mono.when(
                    Mono.<Void>fromRunnable(() -> accountCommandService.deleteAccount(accountId))
                        .subscribeOn(Schedulers.boundedElastic()),
                    Mono.<Void>fromRunnable(() -> productCommandService.deleteProduct(account.getProductId()))
                        .subscribeOn(Schedulers.boundedElastic())
                )
            );
    }
}
