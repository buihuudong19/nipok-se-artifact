package com.openbanking.services.tpp.authcode.pkce;

/**
 * Cặp PKCE (RFC 7636): {@code verifier} (bí mật, giữ ở TPP) + {@code challenge} (công khai, đẩy
 * trong authorization request) + {@code method} ("S256").
 *
 * <p>Value object bất biến — thuận cho test (so khớp challenge = S256(verifier)).
 */
public record Pkce(String verifier, String challenge, String method) {}
