/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.in;

import de.bdr.pidp.issuer.end2end.integration.RestAssuredWebTest;
import de.bdr.pidp.issuer.end2end.requests.RefreshTokenRequestBuilder;
import de.bdr.pidp.issuer.end2end.steps.Steps;
import de.bdr.pidp.issuer.testdata.TestRefreshTokenIssuer;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.not;

class ChallengeAspectITest extends RestAssuredWebTest {

    private final Steps steps = new Steps();

    @Test
    void shouldIssueNewChallenge() {
        // given
        var challenge = steps.doChallenge();
        var refreshTokenDummy = TestRefreshTokenIssuer.buildRefreshToken().serialize();

        // when
        RefreshTokenRequestBuilder.valid(null, challenge.attestationChallenge(), refreshTokenDummy)
            .doRequest()
        .then()
            .status(HttpStatus.BAD_REQUEST)
            .header("OAuth-Client-Attestation-Challenge", not(emptyString()));
    }
}
