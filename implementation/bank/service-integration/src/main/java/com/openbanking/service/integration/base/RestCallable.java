package com.openbanking.service.integration.base;

import org.springframework.web.client.RestClientException;

@FunctionalInterface
public interface RestCallable<T> {
    T call() throws RestClientException;
}