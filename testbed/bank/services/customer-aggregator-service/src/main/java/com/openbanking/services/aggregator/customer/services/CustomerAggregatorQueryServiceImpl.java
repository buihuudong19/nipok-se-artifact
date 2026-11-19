package  com.openbanking.services.aggregator.customer.services;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.web.bind.annotation.RestController;

import com.openbanking.api.aggregator.customer.AccountAggregateSummary;
import com.openbanking.api.aggregator.customer.CustomerAggregateResponse;
import com.openbanking.api.aggregator.customer.CustomerAggregatorQueryService;
import com.openbanking.api.aggregator.customer.CustomerSummary;
import com.openbanking.api.aggregator.customer.PaymentSummary;
import com.openbanking.api.aggregator.customer.ProductSummary;
import com.openbanking.api.aggregator.customer.TransactionSummary;
import com.openbanking.api.core.account.Account;
import com.openbanking.api.core.account.AccountQueryService;
import com.openbanking.api.core.customer.Customer;
import com.openbanking.api.core.customer.CustomerQueryService;
import com.openbanking.api.core.payment.PaymentQueryService;
import com.openbanking.api.core.product.Product;
import com.openbanking.api.core.product.ProductQueryService;
import com.openbanking.api.core.transaction.Transaction;
import com.openbanking.api.core.transaction.TransactionQueryService;
import com.openbanking.api.exceptions.NotFoundException;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@RestController
public class CustomerAggregatorQueryServiceImpl implements CustomerAggregatorQueryService {
    private final CustomerQueryService customerService;
    private final AccountQueryService accountService;
    private final ProductQueryService productService;
    private final TransactionQueryService transactionService;
    private final PaymentQueryService paymentService;

    public CustomerAggregatorQueryServiceImpl(CustomerQueryService customerService, AccountQueryService accountService, ProductQueryService productService, TransactionQueryService transactionService, PaymentQueryService paymentService) {
        this.customerService = customerService;
        this.accountService = accountService;
        this.productService = productService;
        this.transactionService = transactionService;
        this.paymentService = paymentService;
    }

    @Override
    public Mono<CustomerAggregateResponse> getCustomer(UUID customerId) {
        // customerService.getCustomer() now returns Mono<Customer> directly (reactive MongoDB)
        // NotFoundException is already raised inside CustomerQueryServiceImpl via switchIfEmpty
        Mono<Customer> customerMono = customerService.getCustomer(customerId);

        Mono<List<Account>> accountsMono = Mono.fromCallable(() -> accountService.getAccounts(customerId))
            .subscribeOn(Schedulers.boundedElastic());

        return Mono.zip(customerMono, accountsMono)
            .flatMap(tuple -> createCustomerAggregateResponse(tuple.getT1(), tuple.getT2()));
    }

    private Mono<CustomerAggregateResponse> createCustomerAggregateResponse(Customer customer, List<Account> accounts) {
        CustomerSummary customerSummary = CustomerSummary.builder()
            .customerId(customer.getCustomerId())
            .customerName(customer.getCustomerName())
            .dob(customer.getDob())
            .address(customer.getAddress())
            .email(customer.getEmail())
            .phoneNum(customer.getPhoneNum())
            .identityId(customer.getIdentityId())
            .customerType(customer.getCustomerType())
            .kycStatus(customer.getKycStatus())
            .build();

        return Flux.fromIterable(accounts)
            .flatMap(this::buildAccountAggregateSummary)
            .collectList()
            .map(accountSummaries -> CustomerAggregateResponse.builder()
                .customerSummary(customerSummary)
                .accounts(accountSummaries)
                .build());
    }

    private Mono<AccountAggregateSummary> buildAccountAggregateSummary(Account account) {
        Mono<ProductSummary> productMono = Mono.fromCallable(() -> getProductSummary(account.getProductId()))
            .subscribeOn(Schedulers.boundedElastic());
        
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
        
        Mono<List<TransactionSummary>> transactionsMono = Mono.fromCallable(() -> getTransactionSummaries(account.getAccountId()))
            .subscribeOn(Schedulers.boundedElastic());

        return Mono.zip(productMono, paymentsMono, transactionsMono)
            .map(tuple -> AccountAggregateSummary.builder()
                .accountId(account.getAccountId())
                .accountNo(account.getAccountNo())
                .currency(account.getCurrency())
                .accountType(account.getAccountType())
                .status(account.getStatus())
                .openingDate(account.getOpeningDate())
                .balance(account.getBalance())
                .product(tuple.getT1())
                .payments(tuple.getT2())
                .transactions(tuple.getT3())
                .build());
    }

    private ProductSummary getProductSummary(UUID productId) {
        Product product = productService.getProduct(productId);
        if (product == null) {
            throw new NotFoundException("No product found for productId: " + productId);
        }
        return ProductSummary.builder()
            .productId(product.getProductId())
            .productCode(product.getProductCode())
            .productName(product.getProductName())
            .productType(product.getProductType())
            .description(product.getDescription())
            .currency(product.getCurrency())
            .interestRate(product.getInterestRate())
            .build();
    }

    private List<TransactionSummary> getTransactionSummaries(UUID accountId) {
        List<Transaction> transactions = transactionService.getTransactions(accountId);
        return transactions.stream()
            .map(transaction -> TransactionSummary.builder()
                .transId(transaction.getTransId())
                .transDate(transaction.getTransDate())
                .amount(transaction.getAmount())
                .currency(transaction.getCurrency())
                .creditOrDebit(transaction.getCreditOrDebit())
                .description(transaction.getDescription())
                .build())
            .collect(Collectors.toList());
    }
}
