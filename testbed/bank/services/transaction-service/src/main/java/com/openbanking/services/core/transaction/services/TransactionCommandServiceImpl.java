package com.openbanking.services.core.transaction.services;

import java.time.LocalDate;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RestController;

import com.openbanking.api.core.transaction.Transaction;
import com.openbanking.api.core.transaction.TransactionCommandService;
import com.openbanking.api.exceptions.InvalidInputException;
import com.openbanking.api.exceptions.NotFoundException;
import com.openbanking.services.core.transaction.persistence.TransactionEntity;
import com.openbanking.services.core.transaction.persistence.TransactionRepository;

@RestController
public class TransactionCommandServiceImpl implements TransactionCommandService {

    private static final Logger LOG = LoggerFactory.getLogger(TransactionCommandServiceImpl.class);

    private final TransactionRepository repository;
    private final TransactionMapper mapper;

    public TransactionCommandServiceImpl(TransactionRepository repository, TransactionMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    @Override
    @Transactional
    public Transaction createTransaction(Transaction body) {
        validateCreateRequest(body);
        LOG.debug("createTransaction: accountId={}, creditOrDebit={}", body.getAccountId(), body.getCreditOrDebit());
        try {
            TransactionEntity entity = mapper.apiToEntity(body);
            if (entity.getTransId() == null) entity.setTransId(UUID.randomUUID());
            if (entity.getStatus() == null) entity.setStatus(TransactionEntity.TransactionStatus.PENDING);
            if (entity.getTransDate() == null) {
                entity.setTransDate(LocalDate.now());
            }

            TransactionEntity saved = repository.save(entity);
            LOG.debug("createTransaction: created transId={}", saved.getTransId());
            return mapper.entityToApi(saved);

        } catch (DataIntegrityViolationException ex) {
            throw new InvalidInputException("Duplicate transaction entry for accountId: " + body.getAccountId());
        }
    }

    @Override
    @Transactional
    public void deleteTransaction(UUID transId) {
        LOG.debug("deleteTransaction: transId={}", transId);
        TransactionEntity entity = repository.findByTransId(transId)
                .orElseThrow(() -> new NotFoundException("No transaction found for transId: " + transId));
        repository.delete(entity);
    }

    private void validateCreateRequest(Transaction body) {
        if (body.getAccountId() == null)
            throw new InvalidInputException("accountId is required");
        if (body.getAmount() == null || body.getAmount() <= 0)
            throw new InvalidInputException("amount must be greater than zero");
        if (body.getCurrency() == null || body.getCurrency().isBlank())
            throw new InvalidInputException("currency is required");
        if (body.getCreditOrDebit() == null)
            throw new InvalidInputException("creditOrDebit is required");
    }
}
