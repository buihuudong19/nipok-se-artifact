package com.openbanking.services.core.transaction.services;

import java.util.List;

import org.mapstruct.Mapper;

import com.openbanking.api.core.transaction.Transaction;
import com.openbanking.services.core.transaction.persistence.TransactionEntity;
import com.openbanking.util.mapper.BaseMapper;
import com.openbanking.util.mapper.CentralMapperConfig;

@Mapper(config = CentralMapperConfig.class)
public interface TransactionMapper extends BaseMapper<Transaction, TransactionEntity> {

    @Override
    Transaction entityToApi(TransactionEntity entity);

    @Override
    TransactionEntity apiToEntity(Transaction api);

    List<Transaction> entityListToApiList(List<TransactionEntity> entity);
    List<TransactionEntity> apiListToEntityList(List<Transaction> api);
}
