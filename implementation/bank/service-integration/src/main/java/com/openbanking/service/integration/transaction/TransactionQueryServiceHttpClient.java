package com.openbanking.service.integration.transaction;

import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openbanking.api.core.transaction.Transaction;
import com.openbanking.api.core.transaction.TransactionQueryService;
import com.openbanking.service.integration.base.BaseIntegration;

@Service
public class TransactionQueryServiceHttpClient extends BaseIntegration implements TransactionQueryService {

    private final String baseUrl;

    public TransactionQueryServiceHttpClient(ObjectMapper mapper,
                                             WebClient.Builder webClientBuilder,
                                             @Value("${app.services.transaction.url:http://transaction/}") String baseUrl) {
        super(mapper, webClientBuilder);
        this.baseUrl = baseUrl;
    }

    @Override
    public List<Transaction> getTransactions(UUID accountId) {
        if (accountId == null) {
            throw new IllegalArgumentException("Account ID cannot be null or empty");
        }
        String url = baseUrl + "accounts/" + accountId + "/transactions";
        this.log.debug("Will call getTransactions API on URL: {}", url);
        List<Transaction> transactions = getList(url, new ParameterizedTypeReference<List<Transaction>>() {});
        if (transactions == null) {
            log.warn("getTransactions API returned null for accountId: {}", accountId);
            return List.of();
        }
        return transactions;
    }
}
