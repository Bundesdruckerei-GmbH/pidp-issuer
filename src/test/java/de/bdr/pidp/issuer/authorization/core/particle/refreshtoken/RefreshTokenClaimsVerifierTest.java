/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle.refreshtoken;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.Scope;
import de.bdr.pidp.issuer.authorization.config.MetaTestData;
import de.bdr.pidp.issuer.base.constants.AccessTokenClaims;
import de.bdr.pidp.issuer.base.constants.RefreshTokenClaims;
import de.bdr.pidp.issuer.base.jwt.InsufficientScopeException;
import de.bdr.pidp.issuer.testdata.ClientIds;
import de.bdr.pidp.issuer.testdata.TestRefreshTokenIssuer;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RefreshTokenClaimsVerifierTest {
    private final int maxClockSkew = 30;
    private final Scope scope = new Scope("pid");
    private final Base64URL jkt = Base64URL.encode("Ja nee");
    private final RefreshTokenClaimsVerifier verifier = new RefreshTokenClaimsVerifier(
        MetaTestData.AUTH_METADATA.getIssuer(),
        maxClockSkew
    );

    private RefreshTokenSecurityContext context;

    @BeforeEach
    void setUp() {
        context = new RefreshTokenSecurityContext(
            ClientIds.validClientIdForSelfSigned().toString(),
            jkt,
            scope
        );
    }

    @Test
    void success() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt).build();

        Assertions.assertThatNoException().isThrownBy(() -> verifier.verify(claims, context));
    }

    @Test
    void missingIssueTime() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .issueTime(null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT issue time (iat) claim");
    }

    @Test
    void aheadIssueTime() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .issueTime(Date.from(Instant.now().plusSeconds(maxClockSkew * 2)))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT issue time ahead of current time");
    }

    @Test
    void aheadIssueTimeWithinTolerance() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .issueTime(Date.from(Instant.now().plusSeconds(maxClockSkew / 2)))
            .build();

        Assertions.assertThatNoException().isThrownBy(() -> verifier.verify(claims, context));
    }


    @Test
    void missingExpirationTime() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .expirationTime(null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT expiration (exp) claim");
    }

    @Test
    void pastExpirationTime() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .expirationTime(Date.from(Instant.now().minusSeconds(maxClockSkew * 2)))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Expired JWT");
    }

    @Test
    void pastExpirationTimeWithinTolerance() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .issueTime(Date.from(Instant.now().minusSeconds(maxClockSkew / 2)))
            .build();

        Assertions.assertThatNoException().isThrownBy(() -> verifier.verify(claims, context));
    }

    @Test
    void missingIssuer() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .issuer(null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT issuer (iss) claim");
    }

    @Test
    void emptyIssuer() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .issuer("")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT issuer (iss) claim");
    }

    @Test
    void invalidIssuer() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .issuer("invalid")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT issuer does not match expected value");
    }

    @Test
    void missingAudience() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .audience((String) null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT audience (aud) claim");
    }

    @Test
    void emptyAudience() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .audience("")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT audience unknown");
    }

    @Test
    void invalidAudience() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .audience("invalid")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT audience unknown");
    }

    @Test
    void missingSubject() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .subject(null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT subject (sub) claim");
    }

    @Test
    void emptySubject() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .subject("")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT subject (sub) claim");
    }

    @Test
    void missingJWTID() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .jwtID(null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT JWTID (jti) claim");
    }

    @Test
    void emptyJWTID() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .jwtID("")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT JWTID empty");
    }

    @Test
    void missingClientID() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.CLIENT_ID, null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT client ID (client_id) claim");
    }

    @Test
    void emptyClientID() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.CLIENT_ID, "")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT client ID (client_id) claim");
    }

    @Test
    void invalidClientID() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.CLIENT_ID, "invalid")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT client ID does not match expected value");
    }

    @Test
    void invalidClientIDType() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.CLIENT_ID, 42)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Invalid JWT client ID (client_id) claim");
    }

    @Test
    void missingScope() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.SCOPE, null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT scope (scope) claim");
    }

    @Test
    void emptyScope() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.SCOPE, "")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT scope (scope) claim");
    }

    @Test
    void invalidScope() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.SCOPE, "invalid")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(InsufficientScopeException.class)
            .hasMessage("JWT scope is insufficient");
    }

    @Test
    void invalidScopeType() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.SCOPE, 42)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Invalid JWT scope (scope) claim");
    }

    @Test
    void missingSeedCredential() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .claim(RefreshTokenClaims.SEED_CREDENTIAL, null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT seed credential (https://pid-provider.bundesdruckerei.de/seed_credential) claim");
    }

    @Test
    void emptySeedCredential() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .claim(RefreshTokenClaims.SEED_CREDENTIAL, "")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT seed credential (https://pid-provider.bundesdruckerei.de/seed_credential) claim");
    }

    @Test
    void invalidSeedCredentialType() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .claim(RefreshTokenClaims.SEED_CREDENTIAL, 42)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Invalid JWT seed credential (https://pid-provider.bundesdruckerei.de/seed_credential) claim");
    }

    @Test
    void malformedSeedCredential() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .claim(RefreshTokenClaims.SEED_CREDENTIAL, "not-a-jwe")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Malformed JWT seed credential (https://pid-provider.bundesdruckerei.de/seed_credential)");
    }

    @Test
    void missingConfirmation() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .claim("cnf", null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT JWK thumbprint confirmation (cnf.jkt) claim");
    }

    @Test
    void invalidConfirmationType() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .claim("cnf", "invalid")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT JWK thumbprint confirmation (cnf.jkt) claim");
    }

    @Test
    void missingConfirmationThumbprint() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .claim("cnf", Map.of("wrong key", "some value"))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT JWK thumbprint confirmation (cnf.jkt) claim");
    }

    @Test
    void invalidConfirmationKeyType() {
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .claim("cnf", Map.of("jkt", 42))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT JWK thumbprint confirmation (cnf.jkt) claim");
    }

    @Test
    void invalidConfirmationThumbprint() {
        var wrongJkt = Base64URL.encode("wrong-thumbprint").toString();
        var claims = TestRefreshTokenIssuer.defaultClaims(jkt)
            .claim("cnf", Map.of("jkt", wrongJkt))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT JWK thumbprint confirmation does not match expected value");
    }
}
