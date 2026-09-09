/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import com.nimbusds.oauth2.sdk.id.Issuer;
import de.bdr.pidp.issuer.authorization.config.ReadOnlyAuthMetadata;
import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.authorization.core.domain.SeedCredentialReference;
import de.bdr.pidp.issuer.authorization.port.out.AccessTokenSigningPortOut;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.constants.AccessTokenClaims;
import de.bdr.pidp.issuer.base.crypto.KeyID;
import de.bdr.pidp.issuer.base.jwt.JOSEObjectTypes;
import de.bdr.pidp.issuer.base.jwt.RemoteSigner;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;

@NullMarked
@Service
public class AccessTokenIssuer {

    private final AccessTokenSigningPortOut signatureProvider;

    private final Issuer issuer;
    private final Issuer audience;
    private final Duration accessTokenLifetime;
    private final KeyID signingAlias;

    public AccessTokenIssuer(AccessTokenSigningPortOut signatureProvider, ReadOnlyAuthMetadata metadata, AuthorizationConfiguration config) {
        this.signatureProvider = signatureProvider;
        this.issuer = metadata.getIssuer();
        this.audience = metadata.getIssuer(); // (== issuer_config.credential_issuer_identifier)
        this.accessTokenLifetime = config.getAccessTokenLifetime();
        this.signingAlias = new KeyID(config.getAtSigAlias());
    }

    /**
     * @param clientID       client ID
     * @param scope          requested scope from PAR
     * @param jkt            JWK thumbprint of DPoP JWK
     * @param seedRef        ref to the seed credential
     * @param refreshTokenId jti of refresh token
     * @return signed JWT access token
     */
    public SignedJWT buildAccessToken(UUID accessTokenID, String clientID, String scope, Base64URL jkt, SeedCredentialReference seedRef, String refreshTokenId) {
        var keyAttr = signatureProvider.getLatestVersionKeyAttributes(signingAlias);

        var claims = buildClaims(accessTokenID, clientID, scope, jkt, seedRef, refreshTokenId);

        var header = new JWSHeader.Builder(keyAttr.algorithm())
            .type(JOSEObjectTypes.ACCESS_TOKEN)
            .keyID(keyAttr.keyID().toString())
            .build();

        var jwt = new SignedJWT(header, claims);

        Function<byte[], Base64URL> signCallback = hash -> signatureProvider.sign(keyAttr.keyID().keyID(), hash);
        var signer = new RemoteSigner(Set.of(keyAttr.algorithm()), signCallback);
        try {
            jwt.sign(signer);
        } catch (JOSEException e) {
            throw new PidServerException("Could not sign access token", e);
        }

        return jwt;
    }

    private JWTClaimsSet buildClaims(UUID accessTokenID, String clientID, String scope, Base64URL jkt, SeedCredentialReference seedRef, String refreshTokenId) {
        var cnf = new JWKThumbprintConfirmation(jkt).toJWTClaim();
        var now = Instant.now();

        return new JWTClaimsSet.Builder()
            .issuer(issuer.getValue())
            .subject(seedRef.subject())
            .issueTime(Date.from(now))
            .jwtID(accessTokenID.toString())
            .claim(AccessTokenClaims.CLIENT_ID, clientID)
            .claim(AccessTokenClaims.SCOPE, scope)
            .claim(cnf.getKey(), cnf.getValue())

            .audience(audience.getValue())
            .expirationTime(Date.from(now.plus(accessTokenLifetime)))
            .claim(AccessTokenClaims.SEED_CREDENTIAL_REFERENCE, seedRef.jwtID())
            .claim(AccessTokenClaims.REFRESH_TOKEN_REFERENCE, refreshTokenId)
            .build();
    }
}
