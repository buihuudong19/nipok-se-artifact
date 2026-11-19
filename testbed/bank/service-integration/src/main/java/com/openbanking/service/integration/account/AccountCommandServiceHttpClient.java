package com.openbanking.service.integration.account;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openbanking.api.core.account.Account;
import com.openbanking.api.core.account.AccountCommandService;
import com.openbanking.service.integration.base.BaseIntegration;

@Service
public class AccountCommandServiceHttpClient extends BaseIntegration implements AccountCommandService {

    private final String baseUrl;

    public AccountCommandServiceHttpClient(ObjectMapper mapper,
                                           WebClient.Builder webClientBuilder,
                                           @Value("${app.services.account.url:http://account/}") String baseUrl) {
        super(mapper, webClientBuilder);
        this.baseUrl = baseUrl;
    }

    @Override
    public Account createAccount(Account body) {
        String url = baseUrl + "accounts";
        this.log.debug("Will call createAccount API on URL: {}", url);
        return post(url, body, Account.class);
    }

    @Override
    public void deleteAccount(UUID accountId) {
        if (accountId == null) {
            throw new IllegalArgumentException("Account ID cannot be null or empty");
        }
        String url = baseUrl + "accounts/" + accountId;
        this.log.debug("Will call deleteAccount API on URL: {}", url);
        delete(url);
    }
}
