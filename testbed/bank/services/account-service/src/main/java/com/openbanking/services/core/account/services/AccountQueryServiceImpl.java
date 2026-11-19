package com.openbanking.services.core.account.services;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RestController;

import com.openbanking.api.core.account.Account;
import com.openbanking.api.core.account.AccountQueryService;
import com.openbanking.api.exceptions.InvalidInputException;
import com.openbanking.services.core.account.persistence.AccountEntity;
import com.openbanking.services.core.account.persistence.AccountRepository;

@RestController
public class AccountQueryServiceImpl implements AccountQueryService {

    private static final Logger LOG = LoggerFactory.getLogger(AccountQueryServiceImpl.class);
    private final AccountRepository repository;
    private final AccountMapper mapper;

    public AccountQueryServiceImpl(AccountRepository repository, AccountMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }
    
    @Override
    public List<Account> getAccounts(UUID customerId) {
       LOG.debug("/accounts return the found accounts for customerId={}", customerId);
    if (customerId == null) {
        throw new InvalidInputException("Invalid customerId: " + customerId);
    }
    List<AccountEntity> entities = repository.findByCustomerId(customerId);
    if (entities == null || entities.isEmpty()) {
        return Collections.emptyList();  
    }
    return mapper.entityListToApiList(entities);
    }

    @Override
    public Account getAccount(UUID accountId) {
        LOG.debug("/account return the found account for accountId={}", accountId);
        if (accountId == null) {
            throw new InvalidInputException("Invalid accountId: " + accountId);
        }
        return repository.findByAccountId(accountId)
                .map(mapper::entityToApi)
                .orElse(null); 
    }
}
