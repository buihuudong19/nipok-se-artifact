package com.openbanking.services.core.payment;

import java.util.List;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.data.convert.WritingConverter;
import org.springframework.data.r2dbc.convert.R2dbcCustomConversions;
import org.springframework.data.r2dbc.dialect.MySqlDialect;
import org.springframework.lang.NonNull;

@Configuration
public class R2dbcConfig {

    @Bean
    @SuppressWarnings("null")
    R2dbcCustomConversions r2dbcCustomConversions() {
        return R2dbcCustomConversions.of(MySqlDialect.INSTANCE, List.of(
            new UuidToStringConverter(),
            new StringToUuidConverter()
        ));
    }

    @WritingConverter
    static class UuidToStringConverter implements Converter<UUID, String> {
        @Override
        public String convert(@NonNull UUID source) {
            return source.toString();
        }
    }

    @ReadingConverter
    static class StringToUuidConverter implements Converter<String, UUID> {
        @Override
        public UUID convert(@NonNull String source) {
            return UUID.fromString(source);
        }
    }
}
