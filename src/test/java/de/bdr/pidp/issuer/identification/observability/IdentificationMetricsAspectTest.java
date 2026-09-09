/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.observability;

import de.bdr.pidp.issuer.base.VerificationResult;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.micrometer.core.tck.MeterRegistryAssert;
import org.junit.jupiter.api.Test;

class IdentificationMetricsAspectTest {

    private static final String METER_STARTED_NAME = "identification.started";
    private static final String METER_COMPLETED_NAME = "identification.completed";

    private final MeterRegistry registry = new SimpleMeterRegistry();
    private final IdentificationMetricsAspect aspect = new IdentificationMetricsAspect(registry);

    @Test
    void countIdentificationStarted() {
        MeterRegistryAssert.assertThat(registry)
            .hasMeterWithName(METER_STARTED_NAME);

        aspect.countIdentificationStarted();

        MeterRegistryAssert.assertThat(registry)
            .counter(METER_STARTED_NAME)
            .hasCount(1);
    }

    @Test
    void countIdentificationCompletedSuccessfully() {
        MeterRegistryAssert.assertThat(registry)
            .hasMeterWithName(METER_COMPLETED_NAME);

        var response = VerificationResult.success();

        aspect.countIdentificationCompleted(response);


        MeterRegistryAssert.assertThat(registry)
            .counter(METER_COMPLETED_NAME)
            .hasCount(1);
    }

    @Test
    void countIdentificationCompletedFailure() {
        MeterRegistryAssert.assertThat(registry)
            .hasMeterWithName(METER_COMPLETED_NAME);

        var response = VerificationResult.error("Du kommst hier nicht vorbei!");

        aspect.countIdentificationCompleted(response);


        MeterRegistryAssert.assertThat(registry)
            .counter(METER_COMPLETED_NAME)
            .hasCount(0);
    }
}
