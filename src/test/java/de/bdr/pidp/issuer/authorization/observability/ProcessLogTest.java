/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.observability;

import de.bdr.pidp.issuer.eidauthmock.client.model.EidAuthMockBehaviour;
import de.bdr.pidp.issuer.end2end.integration.RestAssuredWebTest;
import de.bdr.pidp.issuer.end2end.requests.MockBehaviorRequestBuilder;
import de.bdr.pidp.issuer.end2end.requests.PushedAuthorizationRequestBuilder;
import de.bdr.pidp.issuer.end2end.steps.Steps;
import de.bdr.pidp.issuer.testdata.TestConfig;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Isolated;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(OutputCaptureExtension.class)
@Isolated
class ProcessLogTest extends RestAssuredWebTest {

    private final Steps steps = new Steps();

    @BeforeEach
    void setUp() {
        new MockBehaviorRequestBuilder().withBehavior(EidAuthMockBehaviour.SUCCESS).withHost(TestConfig.getEidMockHostname()).doRequest();
    }

    @Test
    void processLogPAR(CapturedOutput output) {
        steps.doPAR();

        assertThat(StringUtils.countMatches(output, "bop.app.category=process")).isEqualTo(2);
        assertThat(output)
            .containsOnlyOnce("Incoming request POST /par")
            .containsOnlyOnce("Outgoing response POST /par with status 201 CREATED");
    }

    @Test
    void processLogPARException(CapturedOutput output) {
        PushedAuthorizationRequestBuilder.valid(null).withScope("pod").doRequest();

        assertThat(StringUtils.countMatches(output, "bop.app.category=process")).isEqualTo(2);
        assertThat(output)
            .containsOnlyOnce("Incoming request POST /par")
            .containsOnlyOnce("Outgoing response POST /par with status 400 BAD_REQUEST");
    }

    @Test
    void processLogAuthorize(CapturedOutput output) {
        var parResponse = steps.doPAR();
        steps.doAuthorize(parResponse.requestUri());

        assertThat(StringUtils.countMatches(output, "bop.app.category=process")).isEqualTo(4);
        assertThat(output)
            .containsOnlyOnce("Incoming request GET /authorize")
            .containsOnlyOnce("Outgoing response GET /authorize with status 303 SEE_OTHER");
    }

    @Test
    void processLogFinishAuth(CapturedOutput output) {
        var parResponse = steps.doPAR();
        var authResponse = steps.doAuthorize(parResponse.requestUri());
        steps.doFinishAuthorization(authResponse.issuerState());

        assertThat(StringUtils.countMatches(output, "bop.app.category=process")).isEqualTo(6);
        assertThat(output)
            .containsOnlyOnce("Incoming request GET /finish-authorization")
            .containsOnlyOnce("Outgoing response GET /finish-authorization with status 302 FOUND");
    }

    @Test
    void processLogToken(CapturedOutput output) {
        var parResponse = steps.doPAR();
        var authResponse = steps.doAuthorize(parResponse.requestUri());
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState());
        steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce());

        assertThat(StringUtils.countMatches(output, "bop.app.category=process")).isEqualTo(8);
        assertThat(output)
            .containsOnlyOnce("Incoming request POST /token")
            .containsOnlyOnce("Outgoing response POST /token with status 200 OK");
    }

    @Test
    void processLogRefreshToken(CapturedOutput output) {
        var parResponse = steps.doPAR();
        var authResponse = steps.doAuthorize(parResponse.requestUri());
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState());
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce());
        var rtResponse = steps.doRefreshTokenInitRequest(tokenResponse.refreshToken());
        steps.doRefreshTokenRequest(tokenResponse.refreshToken(), rtResponse.dpopNonce());

        assertThat(StringUtils.countMatches(output, "bop.app.category=process")).isEqualTo(12);
        assertThat(StringUtils.countMatches(output, "Incoming request POST /token")).isEqualTo(3);
        assertThat(StringUtils.countMatches(output, "Outgoing response POST /token with status 200 OK")).isEqualTo(2);
        assertThat(output).containsOnlyOnce("Outgoing response POST /token with status 400 BAD_REQUEST");
    }
}
