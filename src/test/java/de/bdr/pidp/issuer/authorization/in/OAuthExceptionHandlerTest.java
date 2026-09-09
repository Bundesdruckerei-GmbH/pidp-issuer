/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.in;

import com.nimbusds.oauth2.sdk.token.DPoPTokenError;
import de.bdr.pidp.issuer.authorization.config.MetaTestData;
import de.bdr.pidp.issuer.authorization.core.exception.DPoPValidationException;
import de.bdr.pidp.issuer.authorization.core.exception.FinishAuthException;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidClientException;
import de.bdr.pidp.issuer.authorization.core.exception.ParameterTooLongException;
import de.bdr.pidp.issuer.authorization.core.exception.RequestUriExpiredException;
import de.bdr.pidp.issuer.authorization.core.exception.SessionExpiredException;
import de.bdr.pidp.issuer.authorization.port.out.IdentificationFailedException;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.RandomUtil;
import de.bdr.pidp.issuer.sharedtest.ErrorResponseValidation;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import tools.jackson.databind.json.JsonMapper;

import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class OAuthExceptionHandlerTest {

    private final OAuthExceptionHandler oAuthExceptionHandler = new OAuthExceptionHandler(new JsonMapper());

    @DisplayName("Verify mapping of InvalidClientException")
    @Test
    void verifyMappingOfInvalidClientException() {
        var invalidClientException = new InvalidClientException("Client Id unknown");
        var result = oAuthExceptionHandler.handleOAuthException(invalidClientException);

        assertAll(() -> {
            assertNotNull(result);
            assertThat(result.getStatusCode(), is(HttpStatus.BAD_REQUEST));
            assertThat(result.getBody(), notNullValue());
            assertThat(result.getBody().get("error").asString(), is("invalid_client"));
            assertThat(result.getBody().get("error_description").asString(), is("Client Id unknown"));
        });
    }

    @DisplayName("Verify mapping of RequestTooLargeException")
    @Test
    void verifyMappingOfRequestTooLargeException() {
        ParameterTooLongException parameterTooLongException = new ParameterTooLongException("state", 2048);
        var result = oAuthExceptionHandler.handleParameterTooLongException(parameterTooLongException);

        assertAll(() -> {
            assertNotNull(result);
            assertThat(result.getStatusCode(), is(HttpStatus.CONTENT_TOO_LARGE));
            assertThat(result.getBody(), notNullValue());
            assertThat(result.getBody().get("error").asString(), is("invalid_request"));
            assertThat(result.getBody().get("error_description").asString(), is("The state parameter exceeds the maximum permitted size of 2048 bytes"));
        });
    }

    @DisplayName("Verify mapping of UseDpopNonceException")
    @Test
    void verifyMappingOfUseDpopNonceException() {
        var nonce = RandomUtil.randomString();
        var useDpopNonceException = DPoPValidationException.useDPoPNonce(Set.of(), nonce);
        var result = oAuthExceptionHandler.handleOAuthException(useDpopNonceException);

        assertAll(() -> {
            assertNotNull(result);
            assertThat(result.getStatusCode(), is(HttpStatus.BAD_REQUEST));
            assertThat(result.getBody(), notNullValue());
            assertThat(result.getBody().get("error").asString(), is("use_dpop_nonce"));
            assertThat(result.getBody().get("error_description").asString(), is("Use of DPoP nonce required"));
            assertThat(result.getHeaders().get("DPoP-Nonce"), contains(nonce));
        });
    }

    @DisplayName("Verify mapping of RequestUriExpiredException")
    @Test
    void verifyMappingOfRequestUriExpiredException() {
        var dpopTokenError = DPoPTokenError.INVALID_TOKEN
            .setDescription("Request uri expired")
            .setJWSAlgorithms(Set.copyOf(MetaTestData.AUTH_METADATA.getDPoPJWSAlgs()))
            .setRealm("oid4vci");

        var requestUriExpiredException = new RequestUriExpiredException(dpopTokenError);
        var result = oAuthExceptionHandler.handleRequestUriExpiredException(requestUriExpiredException);

        assertAll(() -> {
            assertNotNull(result);
            assertThat(result.getStatusCode(), is(HttpStatus.UNAUTHORIZED));
            assertThat(result.getBody(), nullValue());
            assertThat(result.getHeaders().get("DPoP-Nonce"), nullValue());
        });
        ErrorResponseValidation.checkAuthHeader(result.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE),
            "oid4vci", "invalid_token", "Request uri expired", MetaTestData.AUTH_METADATA.getDPoPJWSAlgs());
    }

    @DisplayName("Verify mapping of FinishAuthException caused by IdentificationFailedException")
    @Test
    void test001() {
        var identificationFailedException = new IdentificationFailedException("user aborted process");
        var finishAuthException = new FinishAuthException(null, null, identificationFailedException);

        var result = oAuthExceptionHandler.handleFinishAuthException(finishAuthException);

        Assertions.assertThat(result).isNotNull();
        Assertions.assertThat(result.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        Assertions.assertThat(result.getHeaders().getFirst(HttpHeaders.LOCATION)).isEqualTo("http://localhost:8080/?error_description=Identification%20failed&error=access_denied");
    }

    @DisplayName("Verify mapping of FinishAuthException caused by PidServerException")
    @Test
    void test002() {
        var serverException = new PidServerException("too bad", new ClassCastException("foo"));
        var finishAuthException = new FinishAuthException("https://redirect.localhost/redirect", "abc321TUV", serverException);

        var result = oAuthExceptionHandler.handleFinishAuthException(finishAuthException);

        Assertions.assertThat(result).isNotNull();
        Assertions.assertThat(result.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        Assertions.assertThat(result.getHeaders().getFirst(HttpHeaders.LOCATION)).isEqualTo("https://redirect.localhost/redirect?error=server_error&state=abc321TUV");
    }

    @DisplayName("Verify mapping of SessionExpiredException")
    @Test
    void test003() {
        var sessionExpiredException = new SessionExpiredException();
        var result = oAuthExceptionHandler.handleSessionExpiredException(sessionExpiredException);

        assertAll(() -> {
            assertNotNull(result);
            assertThat(result.getStatusCode(), is(HttpStatus.UNAUTHORIZED));
            assertThat(result.getBody(), notNullValue());
            assertThat(result.getBody().get("error").asString(), is("access_denied"));
        });
    }
}
