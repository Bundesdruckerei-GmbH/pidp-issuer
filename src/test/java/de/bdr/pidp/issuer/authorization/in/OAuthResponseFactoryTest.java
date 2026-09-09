/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.in;

import de.bdr.pidp.issuer.authorization.core.domain.AccessTokenData;
import de.bdr.pidp.issuer.authorization.core.domain.AuthorizeResult;
import de.bdr.pidp.issuer.authorization.core.domain.ChallengeResult;
import de.bdr.pidp.issuer.authorization.core.domain.FinishAuthorizationResult;
import de.bdr.pidp.issuer.authorization.core.domain.ParResult;
import de.bdr.pidp.issuer.authorization.core.domain.RefreshTokenData;
import de.bdr.pidp.issuer.authorization.core.domain.RefreshTokenResult;
import de.bdr.pidp.issuer.authorization.core.domain.TokenResult;
import de.bdr.pidp.issuer.base.Nonce;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import tools.jackson.databind.JsonNode;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.UUID;

import static de.bdr.pidp.issuer.base.PidDataConst.DPOP_NONCE_HEADER;
import static de.bdr.pidp.issuer.base.PidDataConst.DPOP_SCHEME;
import static de.bdr.pidp.issuer.base.RandomUtil.randomString;
import static de.bdr.pidp.issuer.testdata.TestAccessTokenIssuer.buildAccessToken;
import static de.bdr.pidp.issuer.testdata.TestRefreshTokenIssuer.buildRefreshToken;
import static org.assertj.core.api.Assertions.assertThat;

class OAuthResponseFactoryTest {

    @Test
    void parResponseIsCreatedCorrectly() {
        var parResult = new ParResult("RequestUri", Duration.ofSeconds(60));

        ResponseEntity<JsonNode> parResponse = OAuthResponseFactory.createParResponse(parResult);

        assertThat(parResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(parResponse.getBody()).isNotNull();
        assertThat(parResponse.getBody().get("expires_in").asInt()).isEqualTo(60);
        assertThat(parResponse.getBody().get("request_uri").asString()).isEqualTo("RequestUri");
    }

    @Test
    void authorizeResponseIsCreatedCorrectly() throws URISyntaxException, MalformedURLException {
        var samlRedirectUrlString = "https://saml.request.localhost/path?SAMLRequest=abcde";
        var samlRedirectUrl = new URI(samlRedirectUrlString).toURL();
        var authorizeResult = new AuthorizeResult(samlRedirectUrl);

        ResponseEntity<String> authorizeResponse = OAuthResponseFactory.createAuthorizeResponse(authorizeResult);

        assertThat(authorizeResponse.getStatusCode()).isEqualTo(HttpStatus.SEE_OTHER);
        assertThat(authorizeResponse.getHeaders().getFirst(HttpHeaders.LOCATION)).startsWith(samlRedirectUrlString);
    }

    @Test
    void finishAuthorizationResponseIsCreatedCorrectly() {
        var nonce = new Nonce(randomString(), Duration.ofSeconds(60));
        var redirectUri = "https://redirect.localhost";
        var finishAuthorizationResult = new FinishAuthorizationResult(redirectUri, nonce);

        ResponseEntity<String> finishAuthorizationResponse = OAuthResponseFactory.createFinishAuthorizationResponse(finishAuthorizationResult);

        assertThat(finishAuthorizationResponse.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(finishAuthorizationResponse.getHeaders().getFirst(HttpHeaders.LOCATION)).startsWith(redirectUri);
        assertThat(finishAuthorizationResponse.getHeaders().getFirst(DPOP_NONCE_HEADER)).isEqualTo(nonce.nonce());
    }

    @Test
    void tokenResponseIsCreatedCorrectly() {
        var accessToken = new AccessTokenData(UUID.randomUUID(), buildAccessToken(), DPOP_SCHEME, 60L);
        var refreshToken = new RefreshTokenData(buildRefreshToken(), 3600L);
        var nonce = new Nonce(randomString(), Duration.ofSeconds(60));
        var tokenResult = new TokenResult(accessToken, refreshToken, nonce);

        ResponseEntity<JsonNode> tokenResponse = OAuthResponseFactory.createTokenResponse(tokenResult);

        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(tokenResponse.getHeaders().getFirst(DPOP_NONCE_HEADER)).isEqualTo(nonce.nonce());
        assertThat(tokenResponse.getBody()).isNotNull().hasSize(6);
        assertThat(tokenResponse.getBody().get("access_token").asString()).isEqualTo(accessToken.accessToken().serialize());
        assertThat(tokenResponse.getBody().get("token_type").asString()).isEqualTo(DPOP_SCHEME);
        assertThat(tokenResponse.getBody().get("expires_in").asInt()).isEqualTo(60L);
        assertThat(tokenResponse.getBody().get("refresh_token").asString()).isEqualTo(refreshToken.refreshToken().serialize());
        assertThat(tokenResponse.getBody().get("refresh_token_timeout").asInt()).isEqualTo(3600L);
        assertThat(tokenResponse.getBody().get("authorization_expires_in").asInt()).isEqualTo(3600L);
    }

    @Test
    void refreshTokenResponseIsCreatedCorrectly() {
        var accessToken = new AccessTokenData(UUID.randomUUID(), buildAccessToken(), DPOP_SCHEME, 60L);
        var nonce = new Nonce(randomString(), Duration.ofSeconds(60));
        var refreshTokenResult = new RefreshTokenResult(accessToken, nonce);

        ResponseEntity<JsonNode> refreshTokenResponse = OAuthResponseFactory.createRefreshTokenResponse(refreshTokenResult);

        assertThat(refreshTokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(refreshTokenResponse.getHeaders().getFirst(DPOP_NONCE_HEADER)).isEqualTo(nonce.nonce());
        assertThat(refreshTokenResponse.getBody()).isNotNull().hasSize(3);
        assertThat(refreshTokenResponse.getBody().get("access_token").asString()).isEqualTo(accessToken.accessToken().serialize());
        assertThat(refreshTokenResponse.getBody().get("token_type").asString()).isEqualTo(DPOP_SCHEME);
        assertThat(refreshTokenResponse.getBody().get("expires_in").asInt()).isEqualTo(60L);
    }

    @Test
    void challengeResponseIsCreatedCorrectly() {
        var attestationChallenge = randomString();
        var challengeResult = new ChallengeResult(attestationChallenge);

        ResponseEntity<JsonNode> challengeResponse = OAuthResponseFactory.createChallengeResponse(challengeResult);

        assertThat(challengeResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(challengeResponse.getBody()).isNotNull().hasSize(1);
        assertThat(challengeResponse.getBody().get("attestation_challenge").asString()).isEqualTo(attestationChallenge);
    }
}
