package com.openbanking.services.core.account.services;

import java.time.LocalDate;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RestController;

import com.openbanking.api.core.account.Account;
import com.openbanking.api.core.account.AccountCommandService;
import com.openbanking.api.exceptions.InvalidInputException;
import com.openbanking.api.exceptions.NotFoundException;
import com.openbanking.services.core.account.persistence.AccountEntity;
import com.openbanking.services.core.account.persistence.AccountRepository;

@RestController
public class AccountCommandServiceImpl implements AccountCommandService {

    private static final Logger LOG = LoggerFactory.getLogger(AccountCommandServiceImpl.class);

    private final AccountRepository repository;
    private final AccountMapper mapper;

    public AccountCommandServiceImpl(AccountRepository repository, AccountMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    @Override
    @Transactional
    public Account createAccount(Account body) {
        validateCreateRequest(body);
        LOG.debug("createAccount: customerId={}, productId={}", body.getCustomerId(), body.getProductId());
        try {
            AccountEntity entity = mapper.apiToEntity(body);
            if (entity.getAccountId() == null) entity.setAccountId(UUID.randomUUID());
            if (entity.getAccountNo() == null) entity.setAccountNo(generateAccountNo());
            if (entity.getStatus() == null) entity.setStatus(AccountEntity.AccountStatus.ENABLED);
            if (entity.getOpeningDate() == null) entity.setOpeningDate(LocalDate.now());
            if (entity.getBalance() == null) entity.setBalance(0.0);

            AccountEntity saved = repository.save(entity);
            LOG.debug("createAccount: created accountId={}", saved.getAccountId());
            return mapper.entityToApi(saved);

        } catch (DataIntegrityViolationException ex) {
            throw new InvalidInputException(
                "Duplicate account for customerId: " + body.getCustomerId() + ", productId: " + body.getProductId());
        }
    }

    @Override
    @Transactional
    public void deleteAccount(UUID accountId) {
        LOG.debug("deleteAccount: accountId={}", accountId);
        AccountEntity entity = repository.findByAccountId(accountId)
                .orElseThrow(() -> new NotFoundException("No account found for accountId: " + accountId));
        repository.delete(entity);
    }

    private void validateCreateRequest(Account body) {
        if (body.getCustomerId() == null)
            throw new InvalidInputException("customerId is required");
        if (body.getProductId() == null)
            throw new InvalidInputException("productId is required");
        if (body.getCurrency() == null || body.getCurrency().isBlank())
            throw new InvalidInputException("currency is required");
        if (body.getAccountType() == null)
            throw new InvalidInputException("accountType is required");
    }

    private String generateAccountNo() {
        return String.format("%010d", Math.abs(UUID.randomUUID().getMostSignificantBits() % 10_000_000_000L));
    }
}
