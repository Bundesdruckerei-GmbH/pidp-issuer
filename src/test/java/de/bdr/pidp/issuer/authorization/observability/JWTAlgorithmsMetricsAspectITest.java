/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.observability;

import de.bdr.pidp.issuer.eidauthmock.client.model.EidAuthMockBehaviour;
import de.bdr.pidp.issuer.end2end.integration.RestAssuredWebTest;
import de.bdr.pidp.issuer.end2end.requests.MockBehaviorRequestBuilder;
import de.bdr.pidp.issuer.end2end.requests.PushedAuthorizationRequestBuilder;
import de.bdr.pidp.issuer.end2end.requests.RefreshTokenRequestBuilder;
import de.bdr.pidp.issuer.end2end.requests.TokenRequestBuilder;
import de.bdr.pidp.issuer.end2end.steps.Steps;
import de.bdr.pidp.issuer.testdata.TestConfig;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.tck.MeterRegistryAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.http.HttpStatus;

import static de.bdr.pidp.issuer.authorization.observability.JWTAlgorithmsMetricsAspect.CLIENT_ATTESTATION_METRIC_NAME;
import static de.bdr.pidp.issuer.authorization.observability.JWTAlgorithmsMetricsAspect.CLIENT_ATTESTATION_POP_METRIC_NAME;
import static de.bdr.pidp.issuer.authorization.observability.JWTAlgorithmsMetricsAspect.COUNTER_TAG_KEY;
import static de.bdr.pidp.issuer.authorization.observability.JWTAlgorithmsMetricsAspect.DPOP_METRIC_NAME;
import static io.restassured.RestAssured.given;

@Isolated
class JWTAlgorithmsMetricsAspectITest extends RestAssuredWebTest {

    private static final String EXPECTED_METRIC_TEXT = "%s{" + COUNTER_TAG_KEY + "=\"%s\"} %d.0";

    private static final String PM_CLIENT_ATTESTATION_METRIC_NAME = CLIENT_ATTESTATION_METRIC_NAME.replace(".", "_") + "_total";
    private static final String PM_CLIENT_ATTESTATION_POP_METRIC_NAME = CLIENT_ATTESTATION_POP_METRIC_NAME.replace(".", "_") + "_total";
    private static final String PM_DPOP_METRIC_NAME = DPOP_METRIC_NAME.replace(".", "_") + "_total";

    private static final Tag TAG_ES256 = Tag.of(COUNTER_TAG_KEY, "ES256");

    @LocalManagementPort
    private int managementPort;

    @Autowired
    private MeterRegistry meterRegistry;

    private final Steps steps = new Steps();

    @BeforeEach
    void setUp() {
        new MockBehaviorRequestBuilder().withBehavior(EidAuthMockBehaviour.SUCCESS).withHost(TestConfig.getEidMockHostname()).doRequest();
    }

    @DisplayName("Count client attestation and client attestation pop JWT algs on PAR request")
    @Test
    void test001() {
        // given
        int initialCount = (int) meterRegistry.counter(CLIENT_ATTESTATION_METRIC_NAME, Tags.of(TAG_ES256)).count();
        int initialCountPoP = (int) meterRegistry.counter(CLIENT_ATTESTATION_POP_METRIC_NAME, Tags.of(TAG_ES256)).count();

        // when
        steps.doPAR();

        var expectedCount = initialCount + 1;
        var expectedCountPoP = initialCountPoP + 1;

        // then
        MeterRegistryAssert.assertThat(meterRegistry)
            .counter(CLIENT_ATTESTATION_METRIC_NAME, TAG_ES256)
            .hasCount(expectedCount);

        MeterRegistryAssert.assertThat(meterRegistry)
            .counter(CLIENT_ATTESTATION_POP_METRIC_NAME, TAG_ES256)
            .hasCount(expectedCountPoP);

        given()
            .when()
            .port(managementPort)
            .get("/actuator/prometheus")
            .then()
            .statusCode(HttpStatus.OK.value())
            .body(Matchers.containsString(EXPECTED_METRIC_TEXT.formatted(PM_CLIENT_ATTESTATION_METRIC_NAME, "ES256", expectedCount)))
            .body(Matchers.containsString(EXPECTED_METRIC_TEXT.formatted(PM_CLIENT_ATTESTATION_POP_METRIC_NAME, "ES256", expectedCountPoP)));
    }

    @DisplayName("Count DPoP JWT algs on token request")
    @Test
    void test002() {
        // given
        int initialCount = (int) meterRegistry.counter(DPOP_METRIC_NAME, Tags.of(TAG_ES256)).count();

        // when
        var parResponse = steps.doPAR();
        var authResponse = steps.doAuthorize(parResponse.requestUri());
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState());
        steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce());

        var expectedCount = initialCount + 1;

        // then
        MeterRegistryAssert.assertThat(meterRegistry)
            .counter(DPOP_METRIC_NAME, TAG_ES256)
            .hasCount(expectedCount);

        given()
            .when()
            .port(managementPort)
            .get("/actuator/prometheus")
            .then()
            .statusCode(HttpStatus.OK.value())
            .body(Matchers.containsString(EXPECTED_METRIC_TEXT.formatted(PM_DPOP_METRIC_NAME, "ES256", expectedCount)));
    }

    @DisplayName("No Count of client attestation and client attestation pop JWT algs on failure on PAR request")
    @Test
    void test003() {
        // given
        int initialCount = (int) meterRegistry.counter(CLIENT_ATTESTATION_METRIC_NAME, Tags.of(TAG_ES256)).count();
        int initialCountPoP = (int) meterRegistry.counter(CLIENT_ATTESTATION_POP_METRIC_NAME, Tags.of(TAG_ES256)).count();

        // when
        PushedAuthorizationRequestBuilder.valid(null)
            .withClientId("invalid")
            .doRequest()
            .then()
            .status(HttpStatus.BAD_REQUEST);

        // then
        MeterRegistryAssert.assertThat(meterRegistry)
            .counter(CLIENT_ATTESTATION_METRIC_NAME, TAG_ES256)
            .hasCount(initialCount);

        MeterRegistryAssert.assertThat(meterRegistry)
            .counter(CLIENT_ATTESTATION_POP_METRIC_NAME, TAG_ES256)
            .hasCount(initialCountPoP);
    }

    @DisplayName("No Count of DPoP JWT algs on failure token request")
    @Test
    void test004() {
        // given
        int initialCount = (int) meterRegistry.counter(DPOP_METRIC_NAME, Tags.of(TAG_ES256)).count();

        // when
        var parResponse = steps.doPAR();
        var authResponse = steps.doAuthorize(parResponse.requestUri());
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState());
        TokenRequestBuilder.valid(faResponse.dpopNonce())
            .withAuthorizationCode("invalid")
            .doRequest().then()
            .status(HttpStatus.BAD_REQUEST);

        // then
        MeterRegistryAssert.assertThat(meterRegistry)
            .counter(DPOP_METRIC_NAME, TAG_ES256)
            .hasCount(initialCount);
    }

    @DisplayName("Count DPoP, client attestation and client attestation pop JWT algs on refresh token request")
    @Test
    void test005() {
        // given
        var parResponse = steps.doPAR();
        var authResponse = steps.doAuthorize(parResponse.requestUri());
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState());
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce());
        var rtInitResponse = steps.doRefreshTokenInitRequest(tokenResponse.refreshToken());

        int initialCountCA = (int) meterRegistry.counter(CLIENT_ATTESTATION_METRIC_NAME, Tags.of(TAG_ES256)).count();
        int initialCountCAPoP = (int) meterRegistry.counter(CLIENT_ATTESTATION_POP_METRIC_NAME, Tags.of(TAG_ES256)).count();
        int initialCountDPoP = (int) meterRegistry.counter(DPOP_METRIC_NAME, Tags.of(TAG_ES256)).count();

        // when
        steps.doRefreshTokenRequest(tokenResponse.refreshToken(), rtInitResponse.dpopNonce());

        var expectedCountCA = initialCountCA + 1;
        var expectedCountCAPoP = initialCountCAPoP + 1;
        var expectedCountDPoP = initialCountDPoP + 1;

        // then
        MeterRegistryAssert.assertThat(meterRegistry)
            .counter(CLIENT_ATTESTATION_METRIC_NAME, TAG_ES256)
            .hasCount(expectedCountCA);

        MeterRegistryAssert.assertThat(meterRegistry)
            .counter(CLIENT_ATTESTATION_POP_METRIC_NAME, TAG_ES256)
            .hasCount(expectedCountCAPoP);

        MeterRegistryAssert.assertThat(meterRegistry)
            .counter(DPOP_METRIC_NAME, TAG_ES256)
            .hasCount(expectedCountDPoP);

        given()
            .when()
            .port(managementPort)
            .get("/actuator/prometheus")
            .then()
            .statusCode(HttpStatus.OK.value())
            .body(Matchers.containsString(EXPECTED_METRIC_TEXT.formatted(PM_CLIENT_ATTESTATION_METRIC_NAME, "ES256", expectedCountCA)))
            .body(Matchers.containsString(EXPECTED_METRIC_TEXT.formatted(PM_CLIENT_ATTESTATION_POP_METRIC_NAME, "ES256", expectedCountCAPoP)))
            .body(Matchers.containsString(EXPECTED_METRIC_TEXT.formatted(PM_DPOP_METRIC_NAME, "ES256", expectedCountDPoP)));
    }

    @DisplayName("No count of DPoP, client attestation and client attestation pop JWT algs on failure refresh token request")
    @Test
    void test006() {
        // given
        var parResponse = steps.doPAR();
        var authResponse = steps.doAuthorize(parResponse.requestUri());
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState());
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce());

        int initialCountCA = (int) meterRegistry.counter(CLIENT_ATTESTATION_METRIC_NAME, Tags.of(TAG_ES256)).count();
        int initialCountCAPoP = (int) meterRegistry.counter(CLIENT_ATTESTATION_POP_METRIC_NAME, Tags.of(TAG_ES256)).count();
        int initialCountDPoP = (int) meterRegistry.counter(DPOP_METRIC_NAME, Tags.of(TAG_ES256)).count();

        // when
        RefreshTokenRequestBuilder.valid(tokenResponse.refreshToken(), null, "invalidNonce")
            .doRequest().then()
            .status(HttpStatus.BAD_REQUEST);

        // then
        MeterRegistryAssert.assertThat(meterRegistry)
            .counter(CLIENT_ATTESTATION_METRIC_NAME, TAG_ES256)
            .hasCount(initialCountCA);

        MeterRegistryAssert.assertThat(meterRegistry)
            .counter(CLIENT_ATTESTATION_POP_METRIC_NAME, TAG_ES256)
            .hasCount(initialCountCAPoP);

        MeterRegistryAssert.assertThat(meterRegistry)
            .counter(DPOP_METRIC_NAME, TAG_ES256)
            .hasCount(initialCountDPoP);
    }
}
