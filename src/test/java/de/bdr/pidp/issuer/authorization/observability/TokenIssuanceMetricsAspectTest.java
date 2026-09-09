/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.observability;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.micrometer.core.tck.MeterRegistryAssert;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import tools.jackson.databind.json.JsonMapper;

class TokenIssuanceMetricsAspectTest {

    private static final String METER_RT_NAME = "token.refresh_token.issued";
    private static final String METER_AT_BY_RT_NAME = "token.access_token_by_refresh_token.issued";

    private final MeterRegistry registry = new SimpleMeterRegistry();
    private final TokenIssuanceMetricsAspect aspect = new TokenIssuanceMetricsAspect(registry);

    private final JsonMapper jsonMapper = new JsonMapper();

    @Test
    void countRefreshTokenIssuance() {
        MeterRegistryAssert.assertThat(registry)
            .hasMeterWithName(METER_RT_NAME);

        var response = jsonMapper.createObjectNode();
        response.put("refresh_token", "Den Spinnen folgen... Wieso müssen es unbedingt Spinnen sein?");

        aspect.countRefreshTokenIssued(ResponseEntity.ok(response));

        MeterRegistryAssert.assertThat(registry)
            .counter(METER_RT_NAME)
            .hasCount(1);
    }

    @Test
    void countAccessTokenIssuance() {
        MeterRegistryAssert.assertThat(registry)
            .hasMeterWithName(METER_AT_BY_RT_NAME);

        var response = jsonMapper.createObjectNode();
        response.put("access_token", "Wieso können wir nicht lieber den Schmetterlingen folgen?");

        aspect.countAccessTokenIssued(ResponseEntity.ok(response));

        MeterRegistryAssert.assertThat(registry)
            .counter(METER_AT_BY_RT_NAME)
            .hasCount(1);
    }
}
