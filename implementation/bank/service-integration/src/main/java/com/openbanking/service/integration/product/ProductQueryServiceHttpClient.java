package com.openbanking.service.integration.product;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openbanking.api.core.product.Product;
import com.openbanking.api.core.product.ProductQueryService;
import com.openbanking.service.integration.base.BaseIntegration;

@Service
public class ProductQueryServiceHttpClient extends BaseIntegration implements ProductQueryService {

    private final String baseUrl;

    public ProductQueryServiceHttpClient(ObjectMapper mapper,
                                         WebClient.Builder webClientBuilder,
                                         @Value("${app.services.product.url:http://product/}") String baseUrl) {
        super(mapper, webClientBuilder);
        this.baseUrl = baseUrl;
    }

    @Override
    public Product getProduct(UUID productId) {
        if (productId == null) {
            throw new IllegalArgumentException("Product ID cannot be null or empty");
        }
        String url = baseUrl + "products/" + productId;
        this.log.debug("Will call getProduct API on URL: {}", url);
        return get(url, Product.class);
    }
}
