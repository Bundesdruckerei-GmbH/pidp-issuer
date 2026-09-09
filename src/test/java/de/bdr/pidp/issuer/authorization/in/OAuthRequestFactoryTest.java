/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.in;

import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import de.bdr.pidp.issuer.authorization.core.particle.RequestUtil;
import org.junit.jupiter.api.Test;
import org.springframework.util.MultiValueMap;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static de.bdr.pidp.issuer.testdata.ValidTestData.REDIRECT_URI;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class OAuthRequestFactoryTest {

    private final OAuthRequestFactory oAuthRequestFactory = new OAuthRequestFactory();

    @Test
    void processMultipleValuesForOneParam() {
        MultiValueMap<String, String> allParams = MultiValueMap.fromMultiValue(Map.of("key", List.of("value1", "value2")));
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() -> oAuthRequestFactory.createAuthRequest(allParams))
            .withMessage("multi valued parameters: key");

    }

    @Test
    void processMissingValueForOneParam() {
        var allParams = MultiValueMap.fromMultiValue(Map.of("code_challenge_method", List.of("S256"),
            "code_challenge", List.of("VPvsxc7h-NOKbZX9pKqzgLdc3-3VL_U8B4cKRt6r2xE"),
            "client_id", List.of(UUID.randomUUID().toString()),
            "redirect_uri", List.of(REDIRECT_URI),
            "scope", List.of("pid"),
            "state", List.of(),
            "response_type", List.of("code")
            ));
        var headers = RequestUtil.getAttestationHeaders();
        var parRequest = oAuthRequestFactory.createParRequest(MultiValueMap.fromMultiValue(headers), allParams);
        assertThat(parRequest).isNotNull().extracting("state").isNull();
    }
}
