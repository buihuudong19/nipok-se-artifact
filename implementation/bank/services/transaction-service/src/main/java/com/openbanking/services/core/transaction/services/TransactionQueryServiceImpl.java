package com.openbanking.services.core.transaction.services;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RestController;

import com.openbanking.api.core.transaction.Transaction;
import com.openbanking.api.core.transaction.TransactionQueryService;
import com.openbanking.api.exceptions.InvalidInputException;
import com.openbanking.services.core.transaction.persistence.TransactionEntity;
import com.openbanking.services.core.transaction.persistence.TransactionRepository;

@RestController
public class TransactionQueryServiceImpl implements TransactionQueryService {

    private static final Logger LOG = LoggerFactory.getLogger(TransactionQueryServiceImpl.class);
    private final TransactionRepository repository;
    private final TransactionMapper mapper;

    public TransactionQueryServiceImpl(TransactionRepository repository, TransactionMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    @Override
    public List<Transaction> getTransactions(UUID accountId) {
        LOG.debug("getTransactions: accountId={}", accountId);
        if (accountId == null) {
            throw new InvalidInputException("accountId is required");
        }
        List<TransactionEntity> entities = repository.findByAccountId(accountId);
        if (entities == null || entities.isEmpty()) {
            return Collections.emptyList();
        }
        return mapper.entityListToApiList(entities);
    }


}
