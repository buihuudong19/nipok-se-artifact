package com.openbanking.services.core.transaction.persistence;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.repository.CrudRepository;
import org.springframework.transaction.annotation.Transactional;

public interface TransactionRepository extends CrudRepository<TransactionEntity, Long> {
    @Transactional(readOnly = true)
    Optional<TransactionEntity> findByTransId(UUID transId);
    @Transactional(readOnly = true)
    List<TransactionEntity> findByAccountId(UUID accountId);
}
