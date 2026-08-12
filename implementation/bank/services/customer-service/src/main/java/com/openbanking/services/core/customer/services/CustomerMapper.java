package com.openbanking.services.core.customer.services;

import org.mapstruct.Mapper;

import com.openbanking.api.core.customer.Customer;
import com.openbanking.services.core.customer.persistence.CustomerEntity;
import com.openbanking.util.mapper.BaseMapper;
import com.openbanking.util.mapper.CentralMapperConfig;

@Mapper(config = CentralMapperConfig.class)
public interface CustomerMapper extends BaseMapper<Customer, CustomerEntity> {

    @Override
    Customer entityToApi(CustomerEntity entity);

    @Override
    CustomerEntity apiToEntity(Customer api);
}
