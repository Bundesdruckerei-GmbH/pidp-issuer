/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain;

import de.bdr.pidp.issuer.authorization.core.exception.InvalidClientException;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidGrantException;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import de.bdr.pidp.issuer.authorization.core.particle.RequestUtil;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

class RefreshTokenRequestTest {

    private static final Map<String, String> VALID_PARAMS = RequestUtil.getValidRefreshTokenRequestParams();
    private static final Map<String, List<String>> VALID_HEADERS = TestUtils.getClientAttestationHeaders();

    @Test
    void processHappyFlow() {
        assertThatNoException().isThrownBy(() -> new RefreshTokenRequest(VALID_HEADERS, VALID_PARAMS));
    }

    @ParameterizedTest
    @ValueSource(strings = {"client_id", "refresh_token"})
    void processEmptyAndMissingParams(String name) {
        Map<String, String> params = new HashMap<>(VALID_PARAMS);
        params.put(name, "");
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() -> new RefreshTokenRequest(VALID_HEADERS, params))
            .withMessage(InvalidRequestException.missingParameter(name));
        params.remove(name);
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() -> new RefreshTokenRequest(VALID_HEADERS, params))
            .withMessage(InvalidRequestException.missingParameter(name));
    }

    @Test
    void processInvalidRefreshToken() {
        Map<String, String> params = RequestUtil.getValidRefreshTokenRequestParams();
        params.put("refresh_token", "invalid");
        assertThatExceptionOfType(InvalidGrantException.class).isThrownBy(() -> new RefreshTokenRequest(VALID_HEADERS, params))
            .withMessage("Refresh token invalid");
    }

    @DisplayName("Verify exception when Client Attestation or Client Attestation PoP is unparsable")
    @ParameterizedTest
    @ValueSource(strings = {"oauth-client-attestation", "oauth-client-attestation-pop"})
    void processInvalidAttestationHeaders(String name) {
        Map <String, List<String>> headers = new HashMap<>(VALID_HEADERS);
        headers.replace(name, List.of("invalid"));
        assertThatExceptionOfType(InvalidClientException.class).isThrownBy(() -> new RefreshTokenRequest(headers, VALID_PARAMS));
    }
}
