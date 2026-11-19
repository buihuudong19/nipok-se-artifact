package com.openbanking.services.core.product.persistence;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.repository.CrudRepository;

public interface ProductRepository extends CrudRepository<ProductEntity, String>  {
    Optional<ProductEntity> findByProductId(UUID productId);
}
