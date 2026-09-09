/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.observability;

import de.bdr.pidp.issuer.eidauthmock.client.model.EidAuthMockBehaviour;
import de.bdr.pidp.issuer.end2end.integration.RestAssuredWebTest;
import de.bdr.pidp.issuer.end2end.requests.CredentialRequestBuilder;
import de.bdr.pidp.issuer.end2end.requests.MockBehaviorRequestBuilder;
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
    void processLogNonce(CapturedOutput output) {
        steps.doNonceRequest();

        assertThat(StringUtils.countMatches(output, "bop.app.category=process")).isEqualTo(2);
        assertThat(output)
            .containsOnlyOnce("Incoming request POST /nonce")
            .containsOnlyOnce("Outgoing response POST /nonce with status 200 OK");
    }

    @Test
    void processLogCredential(CapturedOutput output) {
        var parResponse = steps.doPAR();
        var authResponse = steps.doAuthorize(parResponse.requestUri());
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState());
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce());
        var nonceResponse = steps.doNonceRequest();
        CredentialRequestBuilder.validSdJwt(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withProofs(nonceResponse.cNonce(), 1)
            .doRequest();

        assertThat(StringUtils.countMatches(output, "bop.app.category=process")).isEqualTo(12);
        assertThat(output)
            .containsOnlyOnce("Incoming request POST /credential")
            .containsOnlyOnce("Outgoing response POST /credential with status 200 OK, issued 1 credentials");
    }

    @Test
    void processLogEncCredential(CapturedOutput output) {
        var parResponse = steps.doPAR();
        var authResponse = steps.doAuthorize(parResponse.requestUri());
        var faResponse = steps.doFinishAuthorization(authResponse.issuerState());
        var tokenResponse = steps.doTokenRequest(faResponse.code(), faResponse.dpopNonce());
        var nonceResponse = steps.doNonceRequest();
        var issuerMetadataResponse = steps.doCredentialIssuerMetadataRequest();
        CredentialRequestBuilder.validSdJwt(tokenResponse.dpopNonce(), tokenResponse.accessToken())
            .withProofs(nonceResponse.cNonce(), 1)
            .withRequestEncryption(issuerMetadataResponse.requestEncryptionJWK())
            .doRequest();

        assertThat(StringUtils.countMatches(output, "bop.app.category=process")).isEqualTo(12);
        assertThat(output)
            .containsOnlyOnce("Incoming request POST /credential")
            .containsOnlyOnce("Outgoing response POST /credential with status 200 OK, issued 1 credentials");
    }

    @Test
    void processLogCredentialException(CapturedOutput output) {
        CredentialRequestBuilder.validSdJwt("unknown", "unknown")
            .doRequest();

        assertThat(StringUtils.countMatches(output, "bop.app.category=process")).isEqualTo(2);
        assertThat(output)
            .containsOnlyOnce("Incoming request POST /credential")
            .containsOnlyOnce("Outgoing response POST /credential with status 401 UNAUTHORIZED");
    }
}
