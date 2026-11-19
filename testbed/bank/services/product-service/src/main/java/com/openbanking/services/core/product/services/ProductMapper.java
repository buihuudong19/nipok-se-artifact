package com.openbanking.services.core.product.services;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import com.openbanking.api.core.product.Product;
import com.openbanking.services.core.product.persistence.ProductEntity;
import com.openbanking.util.mapper.BaseMapper;
import com.openbanking.util.mapper.CentralMapperConfig;

@Mapper(config = CentralMapperConfig.class)
public interface ProductMapper extends BaseMapper<Product, ProductEntity> {

    @Override
    @Mapping(target = "serviceAddress", ignore = true)
    Product entityToApi(ProductEntity entity);

    @Override
    ProductEntity apiToEntity(Product api);
}