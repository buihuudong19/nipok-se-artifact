package com.openbanking.service.integration.transaction;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openbanking.api.core.transaction.Transaction;
import com.openbanking.api.core.transaction.TransactionCommandService;
import com.openbanking.service.integration.base.BaseIntegration;

@Service
public class TransactionCommandServiceHttpClient extends BaseIntegration implements TransactionCommandService {

    private final String baseUrl;

    public TransactionCommandServiceHttpClient(ObjectMapper mapper,
                                               WebClient.Builder webClientBuilder,
                                               @Value("${app.services.transaction.url:http://transaction/}") String baseUrl) {
        super(mapper, webClientBuilder);
        this.baseUrl = baseUrl;
    }

    @Override
    public Transaction createTransaction(Transaction body) {
        String url = baseUrl + "transactions";
        this.log.debug("Will call createTransaction API on URL: {}", url);
        return post(url, body, Transaction.class);
    }

    @Override
    public void deleteTransaction(UUID transId) {
        if (transId == null) {
            throw new IllegalArgumentException("Transaction ID cannot be null or empty");
        }
        String url = baseUrl + "transactions/" + transId;
        this.log.debug("Will call deleteTransaction API on URL: {}", url);
        delete(url);
    }
}
