package com.openbanking.services.core.payment.persistence;

import java.util.UUID;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface PaymentRepository extends ReactiveCrudRepository<PaymentEntity, Long> {
    Mono<PaymentEntity> findByPaymentId(UUID paymentId);
    Flux<PaymentEntity> findByDebtorAccountId(UUID debtorAccountId);
}
