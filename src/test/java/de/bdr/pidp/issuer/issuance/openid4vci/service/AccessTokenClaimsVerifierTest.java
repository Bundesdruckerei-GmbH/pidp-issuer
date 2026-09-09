/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.Scope;
import de.bdr.pidp.issuer.authorization.config.MetaTestData;
import de.bdr.pidp.issuer.base.constants.AccessTokenClaims;
import de.bdr.pidp.issuer.base.jwt.InsufficientScopeException;
import de.bdr.pidp.issuer.issuance.config.IssuanceTestMetadata;
import de.bdr.pidp.issuer.testdata.TestAccessTokenIssuer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AccessTokenClaimsVerifierTest {
    private final int maxClockSkew = 30;
    private final Scope scope = new Scope("pid");
    private final Base64URL jkt = Base64URL.encode("Ja nee");
    private final AccessTokenClaimsVerifier verifier = new AccessTokenClaimsVerifier(
        MetaTestData.AUTH_METADATA.getIssuer(),
        maxClockSkew
    );

    private AccessTokenSecurityContext context;

    @BeforeEach
    void setUp() {
        context = new AccessTokenSecurityContext(
            IssuanceTestMetadata.ISSUANCE_METADATA.credentialIssuer(),
            scope
        );
    }

    @Test
    void success() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt).build();

        assertThatNoException().isThrownBy(() -> verifier.verify(claims, context));
    }

    @Test
    void missingIssueTime() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .issueTime(null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT issue time (iat) claim");
    }

    @Test
    void aheadIssueTime() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .issueTime(Date.from(Instant.now().plusSeconds(maxClockSkew * 2)))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT issue time ahead of current time");
    }

    @Test
    void aheadIssueTimeWithinTolerance() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .issueTime(Date.from(Instant.now().plusSeconds(maxClockSkew / 2)))
            .build();

        assertThatNoException().isThrownBy(() -> verifier.verify(claims, context));
    }


    @Test
    void missingExpirationTime() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .expirationTime(null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT expiration (exp) claim");
    }

    @Test
    void pastExpirationTime() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .expirationTime(Date.from(Instant.now().minusSeconds(maxClockSkew * 2)))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Expired JWT");
    }

    @Test
    void pastExpirationTimeWithinTolerance() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .issueTime(Date.from(Instant.now().minusSeconds(maxClockSkew / 2)))
            .build();

        assertThatNoException().isThrownBy(() -> verifier.verify(claims, context));
    }

    @Test
    void missingIssuer() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .issuer(null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT issuer (iss) claim");
    }

    @Test
    void emptyIssuer() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .issuer("")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT issuer (iss) claim");
    }

    @Test
    void invalidIssuer() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .issuer("invalid")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT issuer does not match expected value");
    }

    @Test
    void missingAudience() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .audience((String) null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT audience (aud) claim");
    }

    @Test
    void emptyAudience() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .audience("")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT audience unknown");
    }

    @Test
    void invalidAudience() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .audience("invalid")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT audience unknown");
    }

    @Test
    void missingSubject() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .subject(null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT subject (sub) claim");
    }

    @Test
    void emptySubject() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .subject("")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT subject (sub) claim");
    }

    @Test
    void missingJWTID() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .jwtID(null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT JWTID (jti) claim");
    }

    @Test
    void emptyJWTID() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .jwtID("")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("JWT JWTID empty");
    }

    @Test
    void missingClientID() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.CLIENT_ID, null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT client ID (client_id) claim");
    }

    @Test
    void emptyClientID() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.CLIENT_ID, "")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT client ID (client_id) claim");
    }

    @Test
    void invalidClientID() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.CLIENT_ID, "invalid")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Invalid JWT client ID (client_id) format");
    }

    @Test
    void invalidClientIDType() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.CLIENT_ID, 42)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Invalid JWT client ID (client_id) claim");
    }

    @Test
    void missingScope() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.SCOPE, null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT scope (scope) claim");
    }

    @Test
    void emptyScope() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.SCOPE, "")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT scope (scope) claim");
    }

    @Test
    void invalidScope() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.SCOPE, "invalid")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(InsufficientScopeException.class)
            .hasMessage("JWT scope is insufficient");
    }

    @Test
    void invalidScopeType() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.SCOPE, 42)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Invalid JWT scope (scope) claim");
    }

    @Test
    void missingSeedCredentialRef() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.SEED_CREDENTIAL_REFERENCE, null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT seed credential ref (https://pid-provider.bundesdruckerei.de/seed_credential_ref) claim");
    }

    @Test
    void emptySeedCredentialRef() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.SEED_CREDENTIAL_REFERENCE, "")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT seed credential ref (https://pid-provider.bundesdruckerei.de/seed_credential_ref) claim");
    }

    @Test
    void invalidSeedCredentialRef() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.SEED_CREDENTIAL_REFERENCE, "invalid")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Invalid JWT seed credential ref (https://pid-provider.bundesdruckerei.de/seed_credential_ref) format");
    }

    @Test
    void invalidSeedCredentialRefType() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.SEED_CREDENTIAL_REFERENCE, 42)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Invalid JWT seed credential ref (https://pid-provider.bundesdruckerei.de/seed_credential_ref) claim");
    }

    @Test
    void missingRefreshTokenRef() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.REFRESH_TOKEN_REFERENCE, null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT refresh token ref (https://pid-provider.bundesdruckerei.de/refresh_token_ref) claim");
    }

    @Test
    void emptyRefreshTokenRef() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.REFRESH_TOKEN_REFERENCE, "")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT refresh token ref (https://pid-provider.bundesdruckerei.de/refresh_token_ref) claim");
    }

    @Test
    void invalidRefreshTokenRef() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.REFRESH_TOKEN_REFERENCE, "invalid")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Invalid JWT refresh token ref (https://pid-provider.bundesdruckerei.de/refresh_token_ref) format");
    }

    @Test
    void invalidRefreshTokenRefType() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .claim(AccessTokenClaims.REFRESH_TOKEN_REFERENCE, 42)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Invalid JWT refresh token ref (https://pid-provider.bundesdruckerei.de/refresh_token_ref) claim");
    }

    @Test
    void missingConfirmation() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .claim("cnf", null)
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT JWK thumbprint confirmation (cnf.jkt) claim");
    }

    @Test
    void invalidConfirmationType() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .claim("cnf", "invalid")
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT JWK thumbprint confirmation (cnf.jkt) claim");
    }

    @Test
    void missingConfirmationThumbprint() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .claim("cnf", Map.of("wrong key", "some value"))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT JWK thumbprint confirmation (cnf.jkt) claim");
    }

    @Test
    void invalidConfirmationKeyType() {
        var claims = TestAccessTokenIssuer.defaultClaims(jkt)
            .claim("cnf", Map.of("jkt", 42))
            .build();

        assertThatThrownBy(() -> verifier.verify(claims, context))
            .isInstanceOf(BadJWTException.class)
            .hasMessage("Missing JWT JWK thumbprint confirmation (cnf.jkt) claim");
    }
}
