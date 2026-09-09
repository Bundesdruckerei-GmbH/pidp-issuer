/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.observability;

import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.micrometer.core.tck.MeterRegistryAssert;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class CredentialConfigurationMetricMonitorTest {

    public static final String METER_TAG_KEY = "id";
    public static final String METER_USAGE_NAME = "credential.configuration.usage";
    public static final String METER_UNKNOWN_NAME = "credential.configuration.unknown";

    private final MeterRegistry registry = new SimpleMeterRegistry();
    private final CredentialConfigurationMetricMonitor monitor = new CredentialConfigurationMetricMonitor(registry);

    @ParameterizedTest
    @EnumSource(CredentialConfigurationID.class)
    void recordKnownUsages(CredentialConfigurationID id) {
        MeterRegistryAssert.assertThat(registry)
            .hasMeterWithNameAndTagKeys(METER_USAGE_NAME, METER_TAG_KEY);

        monitor.recordUsage(id);

        var tag = Tag.of(METER_TAG_KEY, id.getName());
        MeterRegistryAssert.assertThat(registry)
            .counter(METER_USAGE_NAME, tag)
            .hasCount(1);

        monitor.recordUsage(id.getName());

        MeterRegistryAssert.assertThat(registry)
            .counter(METER_USAGE_NAME, tag)
            .hasCount(2);
    }

    @Test
    void recordUnknownUsages() {
        MeterRegistryAssert.assertThat(registry)
            .hasMeterWithName(METER_UNKNOWN_NAME);

        monitor.recordUnknown();

        MeterRegistryAssert.assertThat(registry)
            .counter(METER_UNKNOWN_NAME)
            .hasCount(1);

        monitor.recordUsage("something else");

        MeterRegistryAssert.assertThat(registry)
            .counter(METER_UNKNOWN_NAME)
            .hasCount(2);
    }
}
