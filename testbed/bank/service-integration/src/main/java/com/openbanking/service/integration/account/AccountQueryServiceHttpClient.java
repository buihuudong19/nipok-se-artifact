package com.openbanking.service.integration.account;

import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openbanking.api.core.account.Account;
import com.openbanking.api.core.account.AccountQueryService;
import com.openbanking.service.integration.base.BaseIntegration;

@Service
public class AccountQueryServiceHttpClient extends BaseIntegration implements AccountQueryService {

    private final String baseUrl;

    public AccountQueryServiceHttpClient(ObjectMapper mapper,
                                         WebClient.Builder webClientBuilder,
                                         @Value("${app.services.account.url:http://account/}") String baseUrl) {
        super(mapper, webClientBuilder);
        this.baseUrl = baseUrl;
    }

    @Override
    public List<Account> getAccounts(UUID customerId) {
        if (customerId == null) {
            throw new IllegalArgumentException("Customer ID cannot be null or empty");
        }
        String url = baseUrl + "customers/" + customerId + "/accounts";
        this.log.debug("Will call getAccounts API on URL: {}", url);
        List<Account> accounts = getList(url, new ParameterizedTypeReference<List<Account>>() {});
        if (accounts == null) {
            log.warn("getAccounts API returned null for customerId: {}", customerId);
            return List.of();
        }
        return accounts;
    }

    @Override
    public Account getAccount(UUID accountId) {
        if (accountId == null) {
            throw new IllegalArgumentException("Account ID cannot be null or empty");
        }
        String url = baseUrl + "accounts/" + accountId;
        this.log.debug("Will call getAccount API on URL: {}", url);
        return get(url, Account.class);
    }
}
