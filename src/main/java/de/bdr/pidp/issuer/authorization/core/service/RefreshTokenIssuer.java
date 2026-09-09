/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.service;

import com.fasterxml.uuid.Generators;
import com.fasterxml.uuid.impl.TimeBasedEpochGenerator;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import com.nimbusds.oauth2.sdk.id.Issuer;
import de.bdr.pidp.issuer.authorization.config.ReadOnlyAuthMetadata;
import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.authorization.core.domain.SeedCredential;
import de.bdr.pidp.issuer.authorization.port.out.RefreshTokenSignerPortOut;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.constants.RefreshTokenClaims;
import de.bdr.pidp.issuer.base.jwt.JOSEObjectTypes;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

@NullMarked
@Service
public class RefreshTokenIssuer {

    private final TimeBasedEpochGenerator uuidGenerator = Generators.timeBasedEpochGenerator();

    private final Issuer issuer;
    private final Issuer audience;
    private final Duration refreshTokenLifetime;
    @Nullable
    private final TemporarySignerProvider temporarySignerProvider;
    @Nullable
    private final RefreshTokenSignerPortOut signerProvider;

    public RefreshTokenIssuer(ReadOnlyAuthMetadata metadata,
                              AuthorizationConfiguration config,
                              @Nullable TemporarySignerProvider temporarySignerProvider,
                              @Nullable RefreshTokenSignerPortOut signerProvider) {
        if (signerProvider == null && temporarySignerProvider == null) {
            throw new PidServerException("No SignerProvider initialized");
        }
        this.issuer = metadata.getIssuer();
        this.audience = metadata.getIssuer();
        this.refreshTokenLifetime = config.getRefreshTokenMaxLifetime();
        this.temporarySignerProvider = temporarySignerProvider;
        this.signerProvider = signerProvider;
    }

    /**
     * @param clientID       client ID
     * @param scope          requested scope from PAR
     * @param jkt            JWK thumbprint of DPoP JWK
     * @param seedCredential the seed credential JWE
     * @return signed JWT refresh token
     */
    public SignedJWT buildRefreshToken(String clientID, String scope, Base64URL jkt, SeedCredential seedCredential) {
        if (signerProvider != null) {
            var signingContext = signerProvider.signingContext();
            var claims = buildClaims(clientID, scope, jkt, seedCredential);
            var header = new JWSHeader.Builder(signingContext.algorithm())
                .type(JOSEObjectTypes.REFRESH_TOKEN)
                .keyID(signingContext.keyID())
                .build();
            var jws = new SignedJWT(header, claims);

            try {
                jws.sign(signingContext.signer());
            } catch (JOSEException e) {
                throw new PidServerException("Could not sign refresh token", e);
            }
            return jws;
        }

        var claims = buildClaims(clientID, scope, jkt, seedCredential);
        var header = new JWSHeader.Builder(JWSAlgorithm.ES384)
            .type(JOSEObjectTypes.REFRESH_TOKEN)
            .keyID(temporarySignerProvider.currentKeyID().value())
            .build();
        var jwt = new SignedJWT(header, claims);

        var signer = temporarySignerProvider.currentSigner();
        try {
            jwt.sign(signer);
        } catch (JOSEException e) {
            throw new PidServerException("Could not sign refresh token", e);
        }
        return jwt;
    }

    private JWTClaimsSet buildClaims(String clientID, String scope, Base64URL jkt, SeedCredential seedCredential) {
        var cnf = new JWKThumbprintConfirmation(jkt).toJWTClaim();
        var now = Instant.now();
        var max = now.plus(refreshTokenLifetime);
        var exp = max.isBefore(seedCredential.exp()) ? max : seedCredential.exp();

        return new JWTClaimsSet.Builder()
            .issuer(issuer.getValue())
            .subject(seedCredential.subject())
            .issueTime(Date.from(now))
            .jwtID(uuidGenerator.generate().toString())
            .claim(RefreshTokenClaims.CLIENT_ID, clientID)
            .claim(RefreshTokenClaims.SCOPE, scope)
            .claim(cnf.getKey(), cnf.getValue())

            .audience(audience.getValue())
            .expirationTime(Date.from(exp))
            .claim(RefreshTokenClaims.SEED_CREDENTIAL, seedCredential.value())
            .build();
    }
}
