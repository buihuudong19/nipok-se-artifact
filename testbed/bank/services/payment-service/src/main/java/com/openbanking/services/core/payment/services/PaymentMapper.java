package com.openbanking.services.core.payment.services;

import org.mapstruct.Mapper;

import com.openbanking.api.core.payment.Payment;
import com.openbanking.services.core.payment.persistence.PaymentEntity;
import com.openbanking.util.mapper.BaseMapper;
import com.openbanking.util.mapper.CentralMapperConfig;

@Mapper(config = CentralMapperConfig.class)
public interface PaymentMapper extends BaseMapper<Payment, PaymentEntity> {

    @Override
    Payment entityToApi(PaymentEntity entity);

    @Override
    PaymentEntity apiToEntity(Payment api);
}
