package com.openbanking.api.core.transaction;

import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;

public interface TransactionCommandService {

  /**
   * @param body A JSON representation of the new transaction
   * @return A JSON representation of the newly created transaction
   */
  @PostMapping(
    value    = "/transactions",
    consumes = "application/json",
    produces = "application/json")
  Transaction createTransaction(@RequestBody Transaction body);

  /**
   * Sample usage: "curl -X DELETE $HOST:$PORT/transactions/{transId}".
   *
   * @param transId Id of the transaction
   */
  @DeleteMapping(value = "/transactions/{transId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  void deleteTransaction(@PathVariable UUID transId);

}
