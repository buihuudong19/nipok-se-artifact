package com.openbanking.services.core.customer.services;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RestController;

import com.openbanking.api.core.customer.Customer;
import com.openbanking.api.core.customer.CustomerQueryService;
import com.openbanking.api.exceptions.InvalidInputException;
import com.openbanking.api.exceptions.NotFoundException;
import com.openbanking.services.core.customer.persistence.CustomerRepository;
import com.openbanking.util.http.ServiceUtil;

import reactor.core.publisher.Mono;

@RestController
public class CustomerQueryServiceImpl implements CustomerQueryService {

    private static final Logger LOG = LoggerFactory.getLogger(CustomerQueryServiceImpl.class);

    private final CustomerRepository repository;
    private final CustomerMapper mapper;
    private final ServiceUtil serviceUtil;

    public CustomerQueryServiceImpl(CustomerRepository repository, CustomerMapper mapper, ServiceUtil serviceUtil) {
        this.repository = repository;
        this.mapper = mapper;
        this.serviceUtil = serviceUtil;
    }

    @Override
    public Mono<Customer> getCustomer(UUID customerId) {
        if (customerId == null) {
            return Mono.error(new InvalidInputException("Invalid customerId: " + customerId));
        }
        LOG.debug("/customers return the found customer for customerId={}", customerId);
        return repository.findByCustomerId(customerId)
            .switchIfEmpty(Mono.error(new NotFoundException("No customer found for customerId: " + customerId)))
            .map(entity -> {
                Customer response = mapper.entityToApi(entity);
                response.setServiceAddress(serviceUtil.getServiceAddress());
                LOG.debug("getCustomer: found customerId: {}", response.getCustomerId());
                return response;
            });
    }
}
