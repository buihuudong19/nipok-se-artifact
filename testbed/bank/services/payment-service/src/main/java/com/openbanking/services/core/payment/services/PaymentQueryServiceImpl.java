package com.openbanking.services.core.payment.services;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RestController;

import com.openbanking.api.core.payment.Payment;
import com.openbanking.api.core.payment.PaymentQueryService;
import com.openbanking.api.exceptions.InvalidInputException;
import com.openbanking.services.core.payment.persistence.PaymentRepository;

import reactor.core.publisher.Flux;

@RestController
public class PaymentQueryServiceImpl implements PaymentQueryService {

    private static final Logger LOG = LoggerFactory.getLogger(PaymentQueryServiceImpl.class);
    private final PaymentRepository repository;
    private final PaymentMapper mapper;

    public PaymentQueryServiceImpl(PaymentRepository repository, PaymentMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    @Override
    public Flux<Payment> getPayments(UUID accountId) {
        LOG.debug("/accounts/{accountId}/payments return the found payments for accountId={}", accountId);
        if (accountId == null) {
            throw new InvalidInputException("Invalid accountId: " + accountId);
        }
        return repository.findByDebtorAccountId(accountId)
            .map(mapper::entityToApi);
    }
}
