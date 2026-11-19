package com.openbanking.service.integration.product;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openbanking.api.core.product.Product;
import com.openbanking.api.core.product.ProductCommandService;
import com.openbanking.service.integration.base.BaseIntegration;

@Service
public class ProductCommandServiceHttpClient extends BaseIntegration implements ProductCommandService {

    private final String baseUrl;

    public ProductCommandServiceHttpClient(ObjectMapper mapper,
                                           WebClient.Builder webClientBuilder,
                                           @Value("${app.services.product.url:http://product/}") String baseUrl) {
        super(mapper, webClientBuilder);
        this.baseUrl = baseUrl;
    }

    @Override
    public Product createProduct(Product body) {
        String url = baseUrl + "products";
        this.log.debug("Will call createProduct API on URL: {}", url);
        return post(url, body, Product.class);
    }

    @Override
    public void deleteProduct(UUID productId) {
        String url = baseUrl + "products/" + productId;
        this.log.debug("Will call deleteProduct API on URL: {}", url);
        delete(url);
    }
}
