/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle.clientattestation;

import com.nimbusds.jwt.proc.BadJWTException;
import de.bdr.pidp.issuer.testdata.ClientIds;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientAttestationPoPClaimsVerifierTest {

    private final int maxClockSkew = 30;
    private final String clientId = ClientIds.validClientIdForSelfSigned().toString();
    private final ClientAttestationPoPClaimsVerifier verifier = new ClientAttestationPoPClaimsVerifier(
        TestUtils.ISSUER_IDENTIFIER_AUDIENCE,
        maxClockSkew
    );
    private final String validChallenge = "valid";

    private ClientAttestationSecurityContext context;

    @BeforeEach
    void setUp() {
        context = new ClientAttestationSecurityContext(
            TestUtils.CLIENT_ATTESTATION_TRUST_ANCHOR_SELF_SIGNED,
            clientId,
            c -> validChallenge.equals(c.getValue())
        );
    }

    @Test
    void success() {
        var claims = TestUtils.getClientAttestationPoPClaimsBuilderWithDefaults(validChallenge).build();

        assertThatNoException().isThrownBy(() -> verifier.verify(claims, context));
    }

    @Test
    void successWithoutChallenge() {
        var claims = TestUtils.getClientAttestationPoPClaimsBuilderWithDefaults(null).build();

        assertThatNoException().isThrownBy(() -> verifier.verify(claims, context));
    }

    @Test
    void successWithoutChallengeCheck() {
        var contextWithoutChallengeCheck = new ClientAttestationSecurityContext(
            TestUtils.CLIENT_ATTESTATION_TRUST_ANCHOR_SELF_SIGNED,
            clientId,
            null
        );
        var claims = TestUtils.getClientAttestationPoPClaimsBuilderWithDefaults(null).build();

        assertThatNoException().isThrownBy(() -> verifier.verify(claims, contextWithoutChallengeCheck));
    }

    @Test
    void missingIssueTime() {
        var claims = TestUtils.getClientAttestationPoPClaimsBuilderWithDefaults(validChallenge)
            .issueTime(null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT issue time (iat) claim");
    }

    @Test
    void aheadIssueTime() {
        var claims = TestUtils.getClientAttestationPoPClaimsBuilderWithDefaults(validChallenge)
            .issueTime(Date.from(Instant.now().plusSeconds(maxClockSkew * 2)))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT issue time ahead of current time");
    }

    @Test
    void aheadIssueTimeWithinTolerance() {
        var claims = TestUtils.getClientAttestationPoPClaimsBuilderWithDefaults(validChallenge)
            .issueTime(Date.from(Instant.now().plusSeconds(maxClockSkew / 2)))
            .build();

        assertThatNoException().isThrownBy(() -> verifier.verify(claims, context));
    }

    @Test
    void missingNotBeforeTime() {
        var claims = TestUtils.getClientAttestationPoPClaimsBuilderWithDefaults(validChallenge)
            .notBeforeTime(null)
            .build();

        assertThatNoException().isThrownBy(() -> verifier.verify(claims, context));
    }

    @Test
    void beforeNotBeforeTime() {
        var claims = TestUtils.getClientAttestationPoPClaimsBuilderWithDefaults(validChallenge)
            .notBeforeTime(Date.from(Instant.now().plusSeconds(maxClockSkew * 2)))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT before use time");
    }

    @Test
    void beforeNotBeforeTimeWithinTolerance() {
        var claims = TestUtils.getClientAttestationPoPClaimsBuilderWithDefaults(validChallenge)
            .notBeforeTime(Date.from(Instant.now().plusSeconds(maxClockSkew / 2)))
            .build();

        assertThatNoException().isThrownBy(() -> verifier.verify(claims, context));
    }

    @Test
    void missingIssuer() {
        var claims = TestUtils.getClientAttestationPoPClaimsBuilderWithDefaults(validChallenge)
            .issuer(null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT issuer (iss) claim");
    }

    @Test
    void emptyIssuer() {
        var claims = TestUtils.getClientAttestationPoPClaimsBuilderWithDefaults(validChallenge)
            .issuer("")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT issuer does not match client_id");
    }

    @Test
    void invalidIssuer() {
        var claims = TestUtils.getClientAttestationPoPClaimsBuilderWithDefaults(validChallenge)
            .issuer("invalid")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT issuer does not match client_id");
    }

    @Test
    void missingAudience() {
        var claims = TestUtils.getClientAttestationPoPClaimsBuilderWithDefaults(validChallenge)
            .audience((String) null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT audience (aud) claim");
    }

    @Test
    void emptyAudience() {
        var claims = TestUtils.getClientAttestationPoPClaimsBuilderWithDefaults(validChallenge)
            .audience("")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT audience unknown");
    }

    @Test
    void invalidAudience() {
        var claims = TestUtils.getClientAttestationPoPClaimsBuilderWithDefaults(validChallenge)
            .audience("invalid")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT audience unknown");
    }

    @Test
    void missingJWTID() {
        var claims = TestUtils.getClientAttestationPoPClaimsBuilderWithDefaults(validChallenge)
            .jwtID(null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT JWTID (jti) claim");
    }

    @Test
    void emptyJWTID() {
        var claims = TestUtils.getClientAttestationPoPClaimsBuilderWithDefaults(validChallenge)
            .jwtID("")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT JWTID empty");
    }

    @Test
    void invalidChallenge() {
        var claims = TestUtils.getClientAttestationPoPClaimsBuilderWithDefaults("invalid")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Unknown or expired JWT challenge");
    }

    @Test
    void invalidChallengeType() {
        var claims = TestUtils.getClientAttestationPoPClaimsBuilderWithDefaults(null)
            .claim("challenge", true)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Invalid JWT challenge (challenge) claim");
    }
}
