package com.openbanking.service.integration.base;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openbanking.api.exceptions.InvalidInputException;
import com.openbanking.api.exceptions.NotFoundException;
import com.openbanking.api.exceptions.ServiceIntegrationException;
import com.openbanking.util.http.HttpErrorInfo;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public abstract class BaseIntegration {
    protected final ObjectMapper mapper;
    protected final Logger log;
    protected final WebClient webClient;

    public BaseIntegration(ObjectMapper mapper, WebClient.Builder webClientBuilder) {
        this.mapper = mapper;
        this.webClient = webClientBuilder.build();
        this.log = LoggerFactory.getLogger(getClass());
    }

    protected <T> T get(String url, Class<T> responseType) {
        return webClient.get()
            .uri(url)
            .retrieve()
            .onStatus(HttpStatusCode::is4xxClientError, this::handle4xxError)
            .onStatus(HttpStatusCode::is5xxServerError, this::handle5xxError)
            .bodyToMono(responseType)
            .block();
    }

    protected <T> T getList(String url, ParameterizedTypeReference<T> responseType) {
        return webClient.get()
            .uri(url)
            .retrieve()
            .onStatus(HttpStatusCode::is4xxClientError, this::handle4xxError)
            .onStatus(HttpStatusCode::is5xxServerError, this::handle5xxError)
            .bodyToMono(responseType)
            .block();
    }

    protected <T> T post(String url, Object request, Class<T> responseType) {
        return webClient.post()
            .uri(url)
            .bodyValue(request)
            .retrieve()
            .onStatus(HttpStatusCode::is4xxClientError, this::handle4xxError)
            .onStatus(HttpStatusCode::is5xxServerError, this::handle5xxError)
            .bodyToMono(responseType)
            .block();
    }

    protected void delete(String url) {
        webClient.delete()
            .uri(url)
            .retrieve()
            .onStatus(HttpStatusCode::is4xxClientError, this::handle4xxError)
            .onStatus(HttpStatusCode::is5xxServerError, this::handle5xxError)
            .bodyToMono(Void.class)
            .block();
    }

    protected <T> Flux<T> getFlux(String url, Class<T> responseType) {
        return webClient.get()
            .uri(url)
            .retrieve()
            .onStatus(HttpStatusCode::is4xxClientError, this::handle4xxError)
            .onStatus(HttpStatusCode::is5xxServerError, this::handle5xxError)
            .bodyToFlux(responseType);
    }

    protected <T> Mono<T> getMono(String url, Class<T> responseType) {
        return webClient.get()
            .uri(url)
            .retrieve()
            .onStatus(HttpStatusCode::is4xxClientError, this::handle4xxError)
            .onStatus(HttpStatusCode::is5xxServerError, this::handle5xxError)
            .bodyToMono(responseType);
    }

    protected <T> Mono<T> postMono(String url, Object request, Class<T> responseType) {
        return webClient.post()
            .uri(url)
            .bodyValue(request)
            .retrieve()
            .onStatus(HttpStatusCode::is4xxClientError, this::handle4xxError)
            .onStatus(HttpStatusCode::is5xxServerError, this::handle5xxError)
            .bodyToMono(responseType);
    }

    protected Mono<Void> deleteMono(String url) {
        return webClient.delete()
            .uri(url)
            .retrieve()
            .onStatus(HttpStatusCode::is4xxClientError, this::handle4xxError)
            .onStatus(HttpStatusCode::is5xxServerError, this::handle5xxError)
            .bodyToMono(Void.class);
    }

    private Mono<? extends Throwable> handle4xxError(ClientResponse response) {
        return response.bodyToMono(String.class).map(body -> {
            String message = extractMessage(body);
            HttpStatus status = HttpStatus.resolve(response.statusCode().value());
            if (HttpStatus.NOT_FOUND == status) return (RuntimeException) new NotFoundException(message);
            if (HttpStatus.UNPROCESSABLE_ENTITY == status) return (RuntimeException) new InvalidInputException(message);
            log.warn("Got unexpected HTTP error: {}, body: {}", status, body);
            return new ServiceIntegrationException(message);
        });
    }

    private Mono<? extends Throwable> handle5xxError(ClientResponse response) {
        return response.bodyToMono(String.class).map(body -> {
            log.error("Server error calling REST service, body: {}", body);
            return new ServiceIntegrationException("REST call failed: " + body);
        });
    }

    private String extractMessage(String body) {
        try {
            return mapper.readValue(body, HttpErrorInfo.class).getMessage();
        } catch (IOException e) {
            return body;
        }
    }
}
