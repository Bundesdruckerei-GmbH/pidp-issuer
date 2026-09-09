/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core.seedcredential;

import com.nimbusds.jwt.proc.BadJWTException;
import de.bdr.pidp.issuer.testdata.TestConfig;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SeedCredentialClaimsVerifierTest {

    private final int maxClockSkew = 30;
    private final String issuerIdentifier = TestConfig.pidiBaseUrl();
    private final SeedCredentialClaimsVerifier verifier = new SeedCredentialClaimsVerifier(issuerIdentifier, maxClockSkew);

    @Test
    void success() {
        var claims = TestUtils.getSeedCredentialClaimsBuilderWithDefaults().build();

        assertThatNoException().isThrownBy(() -> verifier.verify(claims, null));
    }

    @Test
    void missingIssueTime() {
        var claims = TestUtils.getSeedCredentialClaimsBuilderWithDefaults()
            .issueTime(null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, null))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT issue time (iat) claim");
    }

    @Test
    void aheadIssueTime() {
        var claims = TestUtils.getSeedCredentialClaimsBuilderWithDefaults()
            .issueTime(Date.from(Instant.now().plusSeconds(maxClockSkew * 2)))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, null))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT issue time ahead of current time");
    }

    @Test
    void aheadIssueTimeWithinTolerance() {
        var claims = TestUtils.getSeedCredentialClaimsBuilderWithDefaults()
            .issueTime(Date.from(Instant.now().plusSeconds(maxClockSkew / 2)))
            .build();

        assertThatNoException().isThrownBy(() -> verifier.verify(claims, null));
    }

    @Test
    void missingExpirationTime() {
        var claims = TestUtils.getSeedCredentialClaimsBuilderWithDefaults()
            .expirationTime(null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, null))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT expiration (exp) claim");
    }

    @Test
    void pastExpirationTime() {
        var claims = TestUtils.getSeedCredentialClaimsBuilderWithDefaults()
            .expirationTime(Date.from(Instant.now().minusSeconds(maxClockSkew * 2)))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, null))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Expired JWT");
    }

    @Test
    void pastExpirationTimeWithinTolerance() {
        var claims = TestUtils.getSeedCredentialClaimsBuilderWithDefaults()
            .issueTime(Date.from(Instant.now().minusSeconds(maxClockSkew / 2)))
            .build();

        assertThatNoException().isThrownBy(() -> verifier.verify(claims, null));
    }

    @Test
    void missingAudience() {
        var claims = TestUtils.getSeedCredentialClaimsBuilderWithDefaults()
            .audience((String) null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, null))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT audience (aud) claim");
    }

    @Test
    void emptyAudience() {
        var claims = TestUtils.getSeedCredentialClaimsBuilderWithDefaults()
            .audience("")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, null))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT audience unknown");
    }

    @Test
    void invalidAudience() {
        var claims = TestUtils.getSeedCredentialClaimsBuilderWithDefaults()
            .audience("invalid")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, null))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT audience unknown");
    }

    @Test
    void missingSubject() {
        var claims = TestUtils.getSeedCredentialClaimsBuilderWithDefaults()
            .subject(null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, null))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT subject (sub) claim");
    }

    @Test
    void emptySubject() {
        var claims = TestUtils.getSeedCredentialClaimsBuilderWithDefaults()
            .subject("")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, null))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT subject (sub) claim");
    }

    @Test
    void missingJWTID() {
        var claims = TestUtils.getSeedCredentialClaimsBuilderWithDefaults()
            .jwtID(null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, null))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT JWTID (jti) claim");
    }

    @Test
    void emptyJWTID() {
        var claims = TestUtils.getSeedCredentialClaimsBuilderWithDefaults()
            .jwtID("")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, null))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT JWTID empty");
    }
}
