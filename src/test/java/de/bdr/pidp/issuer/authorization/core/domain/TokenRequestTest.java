/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain;

import de.bdr.pidp.issuer.authorization.core.exception.InvalidGrantException;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import de.bdr.pidp.issuer.authorization.core.particle.RequestUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

class TokenRequestTest {
    private static final Map<String, String> VALID_PARAMS = RequestUtil.getValidTokenRequestParams();
    private static final Map<String, List<String>> VALID_HEADERS = Collections.emptyMap();

    @Test
    void processHappyFlow() {
        assertThatNoException().isThrownBy(() -> new TokenRequest(VALID_HEADERS, VALID_PARAMS));
    }

    @ParameterizedTest
    @ValueSource(strings = {"code_verifier", "redirect_uri"})
    void processEmptyAndMissingParams(String name) {
        Map<String, String> params = new HashMap<>(VALID_PARAMS);
        params.put(name, "");
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() -> new TokenRequest(VALID_HEADERS, params))
            .withMessage(InvalidRequestException.missingParameter(name));
        params.remove(name);
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() -> new TokenRequest(VALID_HEADERS, params))
            .withMessage(InvalidRequestException.missingParameter(name));
    }

    @Test
    void processMissingCode() {
        Map<String, String> params = new HashMap<>(VALID_PARAMS);
        params.remove("code");
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() -> new TokenRequest(VALID_HEADERS, params))
            .withMessage(InvalidRequestException.missingParameter("code"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"88", "a-b"})
    void shouldThrowExceptionWhenCodeIsInvalid(String code) {
        Map<String, String> params = new HashMap<>(VALID_PARAMS);
        params.put("code", code);

        assertThatExceptionOfType(InvalidGrantException.class).isThrownBy(() -> new TokenRequest(VALID_HEADERS, params))
            .withMessage("invalid authorization code");
    }
}
