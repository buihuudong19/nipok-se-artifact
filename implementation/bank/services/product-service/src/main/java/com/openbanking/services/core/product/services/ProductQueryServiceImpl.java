package com.openbanking.services.core.product.services;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RestController;

import com.openbanking.api.core.product.Product;
import com.openbanking.api.core.product.ProductQueryService;
import com.openbanking.api.exceptions.InvalidInputException;
import com.openbanking.api.exceptions.NotFoundException;
import com.openbanking.services.core.product.persistence.ProductEntity;
import com.openbanking.services.core.product.persistence.ProductRepository;
import com.openbanking.util.http.ServiceUtil;

@RestController
public class ProductQueryServiceImpl implements ProductQueryService {

    private static final Logger LOG = LoggerFactory.getLogger(ProductQueryServiceImpl.class);

    private final ProductRepository repository;
    private final ProductMapper mapper;
    private final ServiceUtil serviceUtil;

    public ProductQueryServiceImpl(ProductRepository repository, ProductMapper mapper, ServiceUtil serviceUtil) {
        this.repository = repository;
        this.mapper = mapper;
        this.serviceUtil = serviceUtil;
    }

    @Override
    public Product getProduct(UUID productId) {
        if (productId == null) {
            throw new InvalidInputException("Invalid productId: " + productId);
        }

        ProductEntity entity = repository.findByProductId(productId)
            .orElseThrow(() -> new NotFoundException("No product found for productId: " + productId));

        Product response = mapper.entityToApi(entity);
        response.setServiceAddress(serviceUtil.getServiceAddress());
        

        LOG.debug("getProduct: found productId: {}", response.getProductId());

        return response;
    }
}
