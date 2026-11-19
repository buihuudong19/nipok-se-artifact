package com.openbanking.api.core.product;

import java.util.UUID;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

public interface ProductQueryService {

  /**
   * Sample usage: "curl $HOST:$PORT/products/550e8400-e29b-41d4-a716-446655440000".
   *
   * @param productId Id of the product
   * @return the product, if found, else null
   */
  @GetMapping(
    value = "/products/{productId}",
    produces = "application/json")
  Product getProduct(@PathVariable UUID productId);

}
