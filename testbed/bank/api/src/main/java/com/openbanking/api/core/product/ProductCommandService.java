package com.openbanking.api.core.product;

import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;

public interface ProductCommandService {

  /**
   * @param body A JSON representation of the new product
   * @return A JSON representation of the newly created product
   */
  @PostMapping(
    value    = "/products",
    consumes = "application/json",
    produces = "application/json")
  Product createProduct(@RequestBody Product body);

  /**
   * Sample usage: "curl -X DELETE $HOST:$PORT/product/{productId}".
   *
   * @param productId Id of the product
   */
  @DeleteMapping(value = "/products/{productId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  void deleteProduct(@PathVariable UUID productId);

}
