package com.openbanking.services.core.payment.services;

import java.time.LocalDate;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RestController;

import com.openbanking.api.core.payment.Payment;
import com.openbanking.api.core.payment.PaymentCommandService;
import com.openbanking.api.exceptions.InvalidInputException;
import com.openbanking.api.exceptions.NotFoundException;
import com.openbanking.services.core.payment.persistence.PaymentEntity;
import com.openbanking.services.core.payment.persistence.PaymentRepository;

import reactor.core.publisher.Mono;

@RestController
public class PaymentCommandServiceImpl implements PaymentCommandService {

    private static final Logger LOG = LoggerFactory.getLogger(PaymentCommandServiceImpl.class);

    private final PaymentRepository repository;
    private final PaymentMapper mapper;

    public PaymentCommandServiceImpl(PaymentRepository repository, PaymentMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    @Override
    @Transactional
    public Mono<Payment> createPayment(Payment body) {
        validateCreateRequest(body);
        LOG.debug("createPayment: debtorAccountId={}, paymentType={}", body.getDebtorAccountId(), body.getPaymentType());

        PaymentEntity entity = mapper.apiToEntity(body);
        if (entity.getPaymentId() == null) entity.setPaymentId(UUID.randomUUID());
        if (entity.getStatus() == null) entity.setStatus(PaymentEntity.PaymentStatus.PENDING);
        if (entity.getExecutionDate() == null) entity.setExecutionDate(LocalDate.now());

        return repository.save(entity)
            .doOnNext(saved -> LOG.debug("createPayment: created paymentId={}", saved.getPaymentId()))
            .map(mapper::entityToApi)
            .onErrorMap(DataIntegrityViolationException.class,
                ex -> new InvalidInputException("Duplicate payment for debtorAccountId: " + body.getDebtorAccountId()));
    }

    @Override
    @Transactional
    public Mono<Void> deletePayment(UUID paymentId) {
        LOG.debug("deletePayment: paymentId={}", paymentId);
        return repository.findByPaymentId(paymentId)
            .switchIfEmpty(Mono.error(new NotFoundException("No payment found for paymentId: " + paymentId)))
            .flatMap(repository::delete);
    }

    private void validateCreateRequest(Payment body) {
        if (body.getDebtorAccountId() == null)
            throw new InvalidInputException("debtorAccountId is required");
        if (body.getCreditorAccountNo() == null || body.getCreditorAccountNo().isBlank())
            throw new InvalidInputException("creditorAccountNo is required");
        if (body.getAmount() == null || body.getAmount() <= 0)
            throw new InvalidInputException("amount must be greater than zero");
        if (body.getCurrency() == null || body.getCurrency().isBlank())
            throw new InvalidInputException("currency is required");
        if (body.getPaymentType() == null)
            throw new InvalidInputException("paymentType is required");
    }
}
