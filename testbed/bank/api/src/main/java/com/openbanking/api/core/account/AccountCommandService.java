package com.openbanking.api.core.account;

import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;

public interface AccountCommandService {
  /**
   * @param body A JSON representation of the new account
   * @return A JSON representation of the newly created account
   */
  @PostMapping(
    value    = "/accounts",
    consumes = "application/json",
    produces = "application/json")
  Account createAccount(@RequestBody Account body);

  /**
   * Sample usage: "curl -X DELETE $HOST:$PORT/accounts/{accountId}".
   *
   * @param accountId Id of the account
   */
  @DeleteMapping(value = "/accounts/{accountId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  void deleteAccount(@PathVariable UUID accountId);

}
