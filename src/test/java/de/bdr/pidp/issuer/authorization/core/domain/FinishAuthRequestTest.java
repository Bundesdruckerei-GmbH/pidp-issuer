/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain;

import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import de.bdr.pidp.issuer.authorization.core.particle.RequestUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

class FinishAuthRequestTest {

    private static final Map<String, String> VALID_PARAMS = RequestUtil.getValidFinishAuthRequestParams();

    @Test
    void processHappyFlow() {
        assertThatNoException().isThrownBy(() -> new FinishAuthRequest(VALID_PARAMS));
    }

    @Test
    void processEmptyAndMissingParams() {
        Map<String, String> params = new HashMap<>(VALID_PARAMS);
        params.put("issuer_state", "");
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() -> new FinishAuthRequest(params))
            .withMessage(InvalidRequestException.missingParameter("issuer_state"));
        params.remove("issuer_state");
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() -> new FinishAuthRequest(params))
            .withMessage(InvalidRequestException.missingParameter("issuer_state"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"88", "a-b"})
    void shouldThrowExceptionWhenIssuerStateIsInvalid(String issuerState) {
        Map<String, String> params = new HashMap<>(VALID_PARAMS);
        params.put("issuer_state", issuerState);

        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() -> new FinishAuthRequest(params))
            .withMessage("Invalid issuer state " + issuerState);
    }
}
