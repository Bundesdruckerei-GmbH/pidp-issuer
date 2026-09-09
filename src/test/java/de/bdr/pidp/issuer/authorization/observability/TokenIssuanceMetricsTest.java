/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.observability;

import de.bdr.pidp.issuer.eidauthmock.client.model.EidAuthMockBehaviour;
import de.bdr.pidp.issuer.end2end.integration.RestAssuredWebTest;
import de.bdr.pidp.issuer.end2end.requests.MockBehaviorRequestBuilder;
import de.bdr.pidp.issuer.end2end.requests.RefreshTokenRequestBuilder;
import de.bdr.pidp.issuer.end2end.requests.TokenRequestBuilder;
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
import org.springframework.http.HttpStatus;

import static io.restassured.RestAssured.given;

@TestInstance(TestInstance.Lifecycle.PER_METHOD)
@Isolated
class TokenIssuanceMetricsTest extends RestAssuredWebTest {
    @LocalManagementPort
    private int managementPort;

    @Autowired
    private MeterRegistry meterRegistry;

    private final Steps steps = new Steps();

    @BeforeEach
    void setUp() {
        new MockBehaviorRequestBuilder().withBehavior(EidAuthMockBehaviour.SUCCESS).withHost(TestConfig.getEidMockHostname()).doRequest();
    }

    @Test
    void countRefreshTokenIssued() {
        // given
        int initialCount = (int) meterRegistry.counter("token.refresh_token.issued").count();

        // when
        var parResponse = steps.doPAR();
        var authResponse = steps.doAuthorize(parResponse.requestUri());
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState());
        steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce());

        // then
        int expectedCount = initialCount + 1;

        MeterRegistryAssert.assertThat(meterRegistry)
            .counter("token.refresh_token.issued")
            .hasCount(expectedCount);

        given()
            .when()
            .port(managementPort)
            .get("/actuator/prometheus")
            .then()
            .statusCode(HttpStatus.OK.value())
            .body(Matchers.containsString("token_refresh_token_issued_total " + expectedCount + ".0"));
    }

    @Test
    void notCountRefreshTokenOnFailure() {
        // given
        int initialCount = (int) meterRegistry.counter("token.refresh_token.issued").count();

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
            .counter("token.refresh_token.issued")
            .hasCount(initialCount);

        given()
            .when()
            .port(managementPort)
            .get("/actuator/prometheus")
            .then()
            .statusCode(HttpStatus.OK.value())
            .body(Matchers.containsString("token_refresh_token_issued_total " + initialCount + ".0"));
    }

    @Test
    void countAccessTokenByRefreshTokenIssued() {
        // given
        int initialCount = (int) meterRegistry.counter("token.access_token_by_refresh_token.issued").count();

        // when
        var parResponse = steps.doPAR();
        var authResponse = steps.doAuthorize(parResponse.requestUri());
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState());
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce());
        var rtInitResponse = steps.doRefreshTokenInitRequest(tokenResponse.refreshToken());
        steps.doRefreshTokenRequest(tokenResponse.refreshToken(), rtInitResponse.dpopNonce());

        // then
        int expectedCount = initialCount + 1;

        MeterRegistryAssert.assertThat(meterRegistry)
            .counter("token.access_token_by_refresh_token.issued")
            .hasCount(expectedCount);

        given()
            .when()
            .port(managementPort)
            .get("/actuator/prometheus")
            .then()
            .statusCode(HttpStatus.OK.value())
            .body(Matchers.containsString("token_access_token_by_refresh_token_issued_total " + expectedCount + ".0"));
    }

    @Test
    void notCountAccessTokenByRefreshTokenOnFailure() {
        // given
        int initialCount = (int) meterRegistry.counter("token.access_token_by_refresh_token.issued").count();

        // when
        var parResponse = steps.doPAR();
        var authResponse = steps.doAuthorize(parResponse.requestUri());
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState());
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce());
        RefreshTokenRequestBuilder.valid(tokenResponse.refreshToken(), null, "invalidNonce")
            .doRequest().then()
            .status(HttpStatus.BAD_REQUEST);

        // then
        MeterRegistryAssert.assertThat(meterRegistry)
            .counter("token.access_token_by_refresh_token.issued")
            .hasCount(initialCount);

        given()
            .when()
            .port(managementPort)
            .get("/actuator/prometheus")
            .then()
            .statusCode(HttpStatus.OK.value())
            .body(Matchers.containsString("token_access_token_by_refresh_token_issued_total " + initialCount + ".0"));
    }
}
