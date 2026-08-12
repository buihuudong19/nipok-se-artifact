package com.openbanking.services.core.account.persistence;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.transaction.annotation.Transactional;

public interface AccountRepository extends PagingAndSortingRepository<AccountEntity, Long>, CrudRepository<AccountEntity, Long> {
   @Transactional(readOnly = true)
   Optional<AccountEntity> findByAccountId(UUID accountId);
   @Transactional(readOnly = true)
   List<AccountEntity> findByCustomerId(UUID customerId);
}
