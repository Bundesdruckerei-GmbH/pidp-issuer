/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.in;

import com.nimbusds.jose.JWSAlgorithm;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidAccessTokenException;
import de.bdr.pidp.issuer.issuance.openid4vci.out.authorization.AuthorizationDiscoveryAdapter;
import de.bdr.pidp.issuer.sharedtest.ErrorResponseValidation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import tools.jackson.databind.json.JsonMapper;

import java.util.HashSet;
import java.util.List;

import static de.bdr.pidp.issuer.issuance.openid4vci.service.dpop.IssuanceDPoPValidationException.invalidDPoPProof;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@ExtendWith(MockitoExtension.class)
class OpenID4VCIExceptionHandlerTest {
    private static final List<JWSAlgorithm> JWS_ALGS_LIST = JWSAlgorithm.Family.EC.stream().toList();
    private static final HashSet<JWSAlgorithm> JWS_ALGS = new HashSet<>(JWS_ALGS_LIST);

    private final JsonMapper jsonMapper = new JsonMapper();

    @Mock
    private AuthorizationDiscoveryAdapter discovery;

    private OpenID4VCIExceptionHandler openID4VCIExceptionHandler;

    @BeforeEach
    void setUp() {
        Mockito.when(discovery.getDPoPSigningAlgorithms()).thenReturn(JWS_ALGS_LIST);
        openID4VCIExceptionHandler = new OpenID4VCIExceptionHandler(jsonMapper, discovery);
    }

    @DisplayName("Verify mapping of RequestUriExpiredException")
    @Test
    void verifyMappingOfInvalidAccessTokenExceptionAndMissingToken() {
        var invalidAccessTokenException = new InvalidAccessTokenException(InvalidAccessTokenException.Reason.MISSING_TOKEN);

        var result = openID4VCIExceptionHandler.handleInvalidAccessTokenException(invalidAccessTokenException);

        assertAll(() -> {
            assertNotNull(result);
            assertThat(result.getStatusCode(), is(HttpStatus.UNAUTHORIZED));
            assertThat(result.getBody(), nullValue());
            assertThat(result.getHeaders().get("DPoP-Nonce"), nullValue());
        });
        ErrorResponseValidation.checkAuthHeader(result.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE),
            "oid4vci", null, null, JWS_ALGS_LIST);
    }

    @DisplayName("Verify mapping of RequestUriExpiredException")
    @Test
    void verifyMappingOfInvalidAccessTokenExceptionAndUnparseableToken() {
        var invalidAccessTokenException = new InvalidAccessTokenException(InvalidAccessTokenException.Reason.INVALID_TOKEN, "could not parse access token");

        var result = openID4VCIExceptionHandler.handleInvalidAccessTokenException(invalidAccessTokenException);

        assertAll(() -> {
            assertNotNull(result);
            assertThat(result.getStatusCode(), is(HttpStatus.UNAUTHORIZED));
            assertThat(result.getBody(), nullValue());
            assertThat(result.getHeaders().get("DPoP-Nonce"), nullValue());
        });
        ErrorResponseValidation.checkAuthHeader(result.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE),
            "oid4vci", "invalid_token", "could not parse access token", JWS_ALGS_LIST);
    }

    @DisplayName("Verify mapping of RequestUriExpiredException")
    @Test
    void verifyMappingOfIssuanceDPoPValidationException() {
        var issuanceDPoPValidationException = invalidDPoPProof(JWS_ALGS, "DPoP nonce is expired");

        var result = openID4VCIExceptionHandler.handleIssuanceDPoPValidationException(issuanceDPoPValidationException);

        assertAll(() -> {
            assertNotNull(result);
            assertThat(result.getStatusCode(), is(HttpStatus.UNAUTHORIZED));
            assertThat(result.getBody(), nullValue());
            assertThat(result.getHeaders().get("DPoP-Nonce"), nullValue());
        });
        ErrorResponseValidation.checkAuthHeader(result.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE),
            "oid4vci", "invalid_dpop_proof", "DPoP nonce is expired", JWS_ALGS_LIST);
    }
}
