package com.openbanking.services.core.product.services;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.web.bind.annotation.RestController;

import com.openbanking.api.core.product.Product;
import com.openbanking.api.core.product.ProductCommandService;
import com.openbanking.api.exceptions.InvalidInputException;
import com.openbanking.services.core.product.persistence.ProductEntity;
import com.openbanking.services.core.product.persistence.ProductRepository;

@RestController
public class ProductCommandServiceImpl implements ProductCommandService {

    private static final Logger LOG = LoggerFactory.getLogger(ProductCommandServiceImpl.class);

    private final ProductRepository repository;

    private final ProductMapper mapper;

    public ProductCommandServiceImpl(ProductRepository repository, ProductMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }
    
    @Override
    public Product createProduct(Product body) {
        LOG.debug("/product create new product with productCode={}", body.getProductCode());
        try {
            ProductEntity entity = mapper.apiToEntity(body);
            ProductEntity newEntity = repository.save(entity);

            LOG.debug("createProduct: entity created for productId: {}", body.getProductId());
            return mapper.entityToApi(newEntity);

        } catch (DuplicateKeyException dke) {
            throw new InvalidInputException("Duplicate key, Product Id: " + body.getProductId());
        }
    }

    @Override
    public void deleteProduct(UUID productId) {
        LOG.debug("/product delete product with productId={}", productId);
        repository.findByProductId(productId).ifPresent(e -> repository.delete(e));
    }
}
