package com.openbanking.services.core.account.services;

import java.util.List;

import org.mapstruct.Mapper;

import com.openbanking.api.core.account.Account;
import com.openbanking.services.core.account.persistence.AccountEntity;
import com.openbanking.util.mapper.BaseMapper;
import com.openbanking.util.mapper.CentralMapperConfig;

@Mapper(config = CentralMapperConfig.class)
public interface AccountMapper extends BaseMapper<Account, AccountEntity> {

    @Override
    Account entityToApi(AccountEntity entity);

    @Override
    AccountEntity apiToEntity(Account api);

    List<Account> entityListToApiList(List<AccountEntity> entity);
    List<AccountEntity> apiListToEntityList(List<Account> api);
}
