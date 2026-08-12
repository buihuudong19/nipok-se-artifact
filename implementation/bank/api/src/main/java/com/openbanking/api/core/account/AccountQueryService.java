package com.openbanking.api.core.account;

import java.util.List;
import java.util.UUID;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

public interface AccountQueryService {

  /**
   * Sample usage: "curl $HOST:$PORT/customers/{customerId}/accounts".
   *
   * @param customerId Id of the customer
   * @return the accounts of the customer
   */
  @GetMapping(
    value = "/customers/{customerId}/accounts",
    produces = "application/json")
  List<Account> getAccounts(@PathVariable UUID customerId);

  /**
   * Sample usage: "curl $HOST:$PORT/accounts/{accountId}".
   *
   * @param accountId Id of the account
   * @return the account, if found, else null
   */
  @GetMapping(
    value = "/accounts/{accountId}",
    produces = "application/json")
  Account getAccount(@PathVariable UUID accountId);

}
