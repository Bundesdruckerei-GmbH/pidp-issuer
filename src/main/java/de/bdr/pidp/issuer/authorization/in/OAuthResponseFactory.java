/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.in;

import de.bdr.pidp.issuer.authorization.core.domain.AuthorizeResult;
import de.bdr.pidp.issuer.authorization.core.domain.ChallengeResult;
import de.bdr.pidp.issuer.authorization.core.domain.FinishAuthorizationResult;
import de.bdr.pidp.issuer.authorization.core.domain.ParResult;
import de.bdr.pidp.issuer.authorization.core.domain.RefreshTokenResult;
import de.bdr.pidp.issuer.authorization.core.domain.TokenResult;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.jspecify.annotations.NullMarked;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

import static de.bdr.pidp.issuer.base.PidDataConst.DPOP_NONCE_HEADER;

@NullMarked
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class OAuthResponseFactory {
    private static final JsonMapper MAPPER = new JsonMapper();
    private static final String REQUEST_URI = "request_uri";
    private static final String EXPIRES_IN = "expires_in";
    private static final String ACCESS_TOKEN = "access_token";
    private static final String TOKEN_TYPE = "token_type";
    private static final String REFRESH_TOKEN = "refresh_token";
    private static final String REFRESH_TOKEN_TIMEOUT = "refresh_token_timeout";
    private static final String AUTHORIZATION_EXPIRES_IN = "authorization_expires_in";
    private static final String ATTESTATION_CHALLENGE = "attestation_challenge";

    public static ResponseEntity<JsonNode> createParResponse(ParResult parResult) {
        ObjectNode jsonBody = MAPPER.createObjectNode()
            .put(REQUEST_URI, parResult.requestUri())
            .put(EXPIRES_IN, parResult.requestUriLifetime().toSeconds());

        return ResponseEntity
            .status(HttpStatus.CREATED)
            .body(jsonBody);
    }

    public static ResponseEntity<String> createAuthorizeResponse(AuthorizeResult authorizeResult) {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(HttpHeaders.LOCATION, authorizeResult.samlAuthRequestUrl().toString());

        return ResponseEntity
            .status(HttpStatus.SEE_OTHER)
            .header(HttpHeaders.LOCATION, authorizeResult.samlAuthRequestUrl().toString())
            .build();
    }

    public static ResponseEntity<String> createFinishAuthorizationResponse(FinishAuthorizationResult finishAuthorizationResult) {
        HttpHeaders httpHeaders = createHeadersWithNonce(finishAuthorizationResult.nonce().nonce());
        httpHeaders.add(HttpHeaders.LOCATION, finishAuthorizationResult.redirectUri());

        return ResponseEntity
            .status(HttpStatus.FOUND)
            .headers(httpHeaders)
            .build();
    }

    public static ResponseEntity<JsonNode> createTokenResponse(TokenResult tokenResult) {
        HttpHeaders httpHeaders = createHeadersWithNonce(tokenResult.nonce().nonce());

        ObjectNode jsonBody = MAPPER.createObjectNode()
            // accessToken
            .put(ACCESS_TOKEN, tokenResult.accessTokenData().accessToken().serialize())
            .put(TOKEN_TYPE, tokenResult.accessTokenData().tokenType())
            .put(EXPIRES_IN, tokenResult.accessTokenData().expiresIn())
            // refreshToken
            .put(REFRESH_TOKEN, tokenResult.refreshTokenData().refreshToken().serialize())
            .put(REFRESH_TOKEN_TIMEOUT, tokenResult.refreshTokenData().expiresIn())
            .put(AUTHORIZATION_EXPIRES_IN, tokenResult.refreshTokenData().expiresIn());

        return ResponseEntity
            .ok()
            .headers(httpHeaders)
            .body(jsonBody);
    }

    public static ResponseEntity<JsonNode> createRefreshTokenResponse(RefreshTokenResult refreshTokenResult) {
        HttpHeaders httpHeaders = createHeadersWithNonce(refreshTokenResult.nonce().nonce());

        ObjectNode jsonBody = MAPPER.createObjectNode()
            // accessToken
            .put(ACCESS_TOKEN, refreshTokenResult.accessTokenData().accessToken().serialize())
            .put(TOKEN_TYPE, refreshTokenResult.accessTokenData().tokenType())
            .put(EXPIRES_IN, refreshTokenResult.accessTokenData().expiresIn());

        return ResponseEntity
            .ok()
            .headers(httpHeaders)
            .body(jsonBody);
    }

    public static ResponseEntity<JsonNode> createChallengeResponse(ChallengeResult challengeResult) {
        var jsonBody = MAPPER.createObjectNode()
            .put(ATTESTATION_CHALLENGE, challengeResult.attestationChallenge());

        return ResponseEntity.ok(jsonBody);
    }

    private static HttpHeaders createHeadersWithNonce(String nonce) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(DPOP_NONCE_HEADER, nonce);
        return headers;
    }
}
