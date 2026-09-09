/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.testdata;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import de.bdr.pidp.issuer.base.constants.AccessTokenClaims;
import de.bdr.pidp.issuer.base.jwt.JOSEObjectTypes;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

public class TestAccessTokenIssuer {

    public static final ECKey SIGNING_EC_KEY = TestUtils.generateEcKey();

    /**
     * Is not signed by KMS.
     * For unit tests only, not suitable for integration tests.
     */
    public static SignedJWT buildAccessToken(JWTClaimsSet claims) {
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectTypes.ACCESS_TOKEN)
            .keyID(SIGNING_EC_KEY.getKeyID())
            .build();

        var jwt = new SignedJWT(header, claims);

        try {
            var signer = new ECDSASigner(SIGNING_EC_KEY);
            jwt.sign(signer);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        return jwt;
    }

    public static SignedJWT buildAccessToken() {
        var claims = defaultClaims(Base64URL.encode("dummy")).build();
        return buildAccessToken(claims);
    }

    public static JWTClaimsSet.Builder defaultClaims(Base64URL jkt) {
        var cnf = new JWKThumbprintConfirmation(jkt).toJWTClaim();
        var now = Instant.now();

        return new JWTClaimsSet.Builder()
            .issuer(TestConfig.pidiBaseUrl())
            .subject("pseudonym")
            .issueTime(Date.from(now))
            .jwtID(UUID.randomUUID().toString())
            .claim(AccessTokenClaims.CLIENT_ID, ClientIds.validClientIdForSelfSigned().toString())
            .claim(AccessTokenClaims.SCOPE, "pid")
            .claim(cnf.getKey(), cnf.getValue())

            .audience(TestConfig.pidiBaseUrl())
            .expirationTime(Date.from(now.plus(Duration.ofMinutes(60))))
            .claim(AccessTokenClaims.SEED_CREDENTIAL_REFERENCE, UUID.randomUUID().toString())
            .claim(AccessTokenClaims.REFRESH_TOKEN_REFERENCE, UUID.randomUUID().toString());
    }
}
