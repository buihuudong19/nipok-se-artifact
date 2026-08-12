package com.openbanking.services.core.customer.services;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.web.bind.annotation.RestController;

import com.openbanking.api.core.customer.Customer;
import com.openbanking.api.core.customer.CustomerCommandService;
import com.openbanking.api.exceptions.InvalidInputException;
import com.openbanking.services.core.customer.persistence.CustomerEntity;
import com.openbanking.services.core.customer.persistence.CustomerRepository;

import reactor.core.publisher.Mono;

@RestController
public class CustomerCommandServiceImpl implements CustomerCommandService {

    private static final Logger LOG = LoggerFactory.getLogger(CustomerCommandServiceImpl.class);
    private final CustomerRepository repository;
    private final CustomerMapper mapper;

    public CustomerCommandServiceImpl(CustomerRepository repository, CustomerMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    @Override
    public Mono<Customer> createCustomer(Customer body) {
        validateCreateRequest(body);
        LOG.debug("createCustomer: identityId={}", body.getIdentityId());

        CustomerEntity entity = mapper.apiToEntity(body);
        if (entity.getCustomerId() == null) entity.setCustomerId(UUID.randomUUID());
        if (entity.getKycStatus() == null) entity.setKycStatus(CustomerEntity.KycStatus.PENDING);
        if (entity.getRiskRate() == null) entity.setRiskRate(CustomerEntity.RiskRate.LOW);

        return repository.save(entity)
            .map(saved -> {
                LOG.debug("createCustomer: created customerId={}", saved.getCustomerId());
                return mapper.entityToApi(saved);
            })
            .onErrorMap(DuplicateKeyException.class, dke ->
                new InvalidInputException("Duplicate key, identityId: " + body.getIdentityId()));
    }

    @Override
    public Mono<Void> deleteCustomer(UUID customerId) {
        LOG.debug("deleteCustomer: customerId={}", customerId);
        return repository.findByCustomerId(customerId)
            .flatMap(repository::delete);
    }

    private void validateCreateRequest(Customer body) {
        if (body.getIdentityId() == null || body.getIdentityId().isBlank())
            throw new InvalidInputException("identityId is required");
        if (body.getCustomerName() == null || body.getCustomerName().isBlank())
            throw new InvalidInputException("customerName is required");
        if (body.getEmail() == null || body.getEmail().isBlank())
            throw new InvalidInputException("email is required");
        if (body.getCustomerType() == null)
            throw new InvalidInputException("customerType is required");
    }
}
