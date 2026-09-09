/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain;

import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import de.bdr.pidp.issuer.authorization.core.particle.RequestUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

class AuthRequestTest {

    private static final Map<String, String> VALID_PARAMS = RequestUtil.getValidAuthRequestParams();

    @Test
    void processHappyFlow() {
        assertThatNoException().isThrownBy(() -> new AuthRequest(VALID_PARAMS));
    }

    @Test
    void processMissingClientId() {
        Map<String, String> params = new HashMap<>(VALID_PARAMS);
        params.remove("client_id");
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() -> new AuthRequest(params))
            .withMessage(InvalidRequestException.missingParameter("client_id"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"urn:ietf:params:oauth:request_uri:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "urn:ietf:params:oauth:request_uri",
        "urn:ietf:params:oauth:request_uri.abcdefghijklmnopqrstuv"
    })
    @NullAndEmptySource
    void processInvalidRequestUri(String requestUri) {
        Map<String, String> params = new HashMap<>(VALID_PARAMS);
        params.replace("request_uri", requestUri);

        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() -> new AuthRequest(params))
            .withMessage("Invalid request_uri: " + requestUri);
    }
}
