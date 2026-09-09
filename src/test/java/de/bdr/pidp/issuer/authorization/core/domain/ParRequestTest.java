/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain;

import de.bdr.pidp.issuer.authorization.core.exception.InvalidClientException;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import de.bdr.pidp.issuer.authorization.core.particle.RequestUtil;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

class ParRequestTest {

    private static Stream<Arguments> invalidParamsProvider() {
        return Stream.of(
            Arguments.arguments("response_type", " ", "response_type must not be empty")
        );
    }

    private static final Map<String, String> VALID_PARAMS = RequestUtil.getValidParRequestParams();
    private static final Map<String, List<String>> VALID_HEADERS = TestUtils.getClientAttestationHeaders();

    @Test
    void processHappyFlow() {
        assertThatNoException().isThrownBy(() -> new ParRequest(VALID_HEADERS, VALID_PARAMS));
    }

    @ParameterizedTest
    @ValueSource(strings = {"client_id", "code_challenge_method", "code_challenge", "redirect_uri", "scope", "response_type"})
    void processEmptyAndMissingParams(String name) {
        Map<String, String> params = new HashMap<>(VALID_PARAMS);
        params.put(name, "");
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() -> new ParRequest(VALID_HEADERS, params))
            .withMessage(InvalidRequestException.missingParameter(name));
        params.remove(name);
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() -> new ParRequest(VALID_HEADERS, params))
            .withMessage(InvalidRequestException.missingParameter(name));
    }

    @ParameterizedTest
    @MethodSource("invalidParamsProvider")
    void processInvalidParam(String name, String value, String message) {
        Map<String, String> params = new HashMap<>(VALID_PARAMS);
        params.replace(name, value);
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() -> new ParRequest(VALID_HEADERS, params))
            .withMessage(message);
    }

    @ParameterizedTest
    @ValueSource(strings = {"oauth-client-attestation", "oauth-client-attestation-pop"})
    void processEmptyAndMissingAttestationHeaders(String name) {
        Map <String, List<String>> headers = new HashMap<>(VALID_HEADERS);
        headers.replace(name, Collections.emptyList());
        assertThatExceptionOfType(InvalidClientException.class).isThrownBy(() -> new ParRequest(headers, VALID_PARAMS));
        headers.remove(name);
        assertThatExceptionOfType(InvalidClientException.class).isThrownBy(() -> new ParRequest(headers, VALID_PARAMS));
    }

    @DisplayName("Verify exception when Client Attestation or Client Attestation PoP is unparsable")
    @ParameterizedTest
    @ValueSource(strings = {"oauth-client-attestation", "oauth-client-attestation-pop"})
    void processInvalidAttestationHeaders(String name) {
        Map <String, List<String>> headers = new HashMap<>(VALID_HEADERS);
        headers.replace(name, List.of("invalid"));
        assertThatExceptionOfType(InvalidClientException.class).isThrownBy(() -> new ParRequest(headers, VALID_PARAMS));
    }
}
