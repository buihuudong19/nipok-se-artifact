package com.openbanking.util.mapper;

public interface BaseMapper<API, ENTITY> {
    API entityToApi(ENTITY entity);
    ENTITY apiToEntity(API api);
}
