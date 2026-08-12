package com.openbanking.api.core.transaction;

import java.util.List;
import java.util.UUID;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

public interface TransactionQueryService {

  /**
   * Sample usage: "curl $HOST:$PORT/accounts/{accountId}/transactions".
   *
   * @param accountId Id of the account
   * @return the transactions of the account
   */
  @GetMapping(
    value = "/accounts/{accountId}/transactions",
    produces = "application/json")
  List<Transaction> getTransactions(@PathVariable UUID accountId);

}
