package com.openbanking.services.tpp.authcode.pkce;

/**
 * PKCE pair (RFC 7636): {@code verifier} (secret, kept at the TPP) + {@code challenge} (public, pushed
 * in the authorization request) + {@code method} ("S256").
 *
 * <p>Immutable value object - convenient for tests (challenge = S256(verifier)).
 */
public record Pkce(String verifier, String challenge, String method) {}
