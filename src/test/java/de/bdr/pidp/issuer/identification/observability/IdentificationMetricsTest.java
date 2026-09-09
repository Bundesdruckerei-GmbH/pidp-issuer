/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.observability;

import de.bdr.pidp.issuer.eidauthmock.client.model.EidAuthMockBehaviour;
import de.bdr.pidp.issuer.end2end.integration.RestAssuredWebTest;
import de.bdr.pidp.issuer.end2end.requests.FinishAuthorizationRequestBuilder;
import de.bdr.pidp.issuer.end2end.requests.MockBehaviorRequestBuilder;
import de.bdr.pidp.issuer.end2end.steps.Steps;
import de.bdr.pidp.issuer.testdata.TestConfig;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.tck.MeterRegistryAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.parallel.Isolated;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;

import static io.restassured.RestAssured.given;

@TestInstance(TestInstance.Lifecycle.PER_METHOD)
@Isolated
class IdentificationMetricsTest extends RestAssuredWebTest {

    @LocalManagementPort
    private int managementPort;

    @Autowired
    private MeterRegistry meterRegistry;

    private final Steps steps = new Steps();

    @BeforeEach
    void setUp() {
        configureEIDMockBehaviour(EidAuthMockBehaviour.SUCCESS);
    }

    @Test
    void countIdentificationStarted() {
        // given
        int initialCount = (int) meterRegistry.counter("identification.started").count();

        // when
        var parResponse = steps.doPAR();
        steps.doAuthorize(parResponse.requestUri());

        // then
        int expectedCount = initialCount + 1;

        MeterRegistryAssert.assertThat(meterRegistry)
            .counter("identification.started")
            .hasCount(expectedCount);

        given()
            .when()
            .port(managementPort)
            .get("/actuator/prometheus")
            .then()
            .statusCode(HttpStatus.OK.value())
            .body(Matchers.containsString("identification_started_total " + expectedCount + ".0"));
    }

    @Test
    void countIdentificationCompletedSuccessfully() {
        // given
        int initialCount = (int) meterRegistry.counter("identification.completed").count();

        // when
        var parResponse = steps.doPAR();
        var authResponse = steps.doAuthorize(parResponse.requestUri());
        steps.doFinishAuthorization(authResponse.issuerState());

        // then
        int expectedCount = initialCount + 1;

        MeterRegistryAssert.assertThat(meterRegistry)
            .counter("identification.completed")
            .hasCount(expectedCount);

        given()
            .when()
            .port(managementPort)
            .get("/actuator/prometheus")
            .then()
            .statusCode(HttpStatus.OK.value())
            .body(Matchers.containsString("identification_completed_total " + expectedCount + ".0"));
    }

    @Test
    void countIdentificationCompletedFailure() {
        // given
        int initialCount = (int) meterRegistry.counter("identification.completed").count();

        // when
        configureEIDMockBehaviour(EidAuthMockBehaviour.OUTDATED_DOCUMENT);
        var parResponse = steps.doPAR();
        var authResponse = steps.doAuthorize(parResponse.requestUri());
        FinishAuthorizationRequestBuilder.valid(authResponse.issuerState())
            .doRequest().then()
            .status(HttpStatus.FOUND)
            .header(HttpHeaders.LOCATION, Matchers.containsString("error="));

        // then
        MeterRegistryAssert.assertThat(meterRegistry)
            .counter("identification.completed")
            .hasCount(initialCount);

        given()
            .when()
            .port(managementPort)
            .get("/actuator/prometheus")
            .then()
            .statusCode(HttpStatus.OK.value())
            .body(Matchers.containsString("identification_completed_total " + initialCount + ".0"));
    }

    private static void configureEIDMockBehaviour(EidAuthMockBehaviour behaviour) {
        new MockBehaviorRequestBuilder().withBehavior(behaviour).withHost(TestConfig.getEidMockHostname()).doRequest();
    }
}
