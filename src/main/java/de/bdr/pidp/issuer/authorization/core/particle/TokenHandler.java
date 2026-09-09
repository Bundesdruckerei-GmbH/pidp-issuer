/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import com.fasterxml.uuid.Generators;
import com.fasterxml.uuid.impl.TimeBasedEpochGenerator;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.authorization.core.domain.AccessTokenData;
import de.bdr.pidp.issuer.authorization.core.domain.SeedCredential;
import de.bdr.pidp.issuer.authorization.core.domain.SeedCredentialReference;
import de.bdr.pidp.issuer.authorization.core.domain.data.RefreshTokenAuthSession;
import de.bdr.pidp.issuer.authorization.core.domain.data.TokenAuthSession;
import de.bdr.pidp.issuer.authorization.core.service.AccessTokenIssuer;
import org.springframework.stereotype.Component;

import java.time.Duration;

import static de.bdr.pidp.issuer.base.PidDataConst.DPOP_SCHEME;

@Component
public class TokenHandler {

    private final TimeBasedEpochGenerator uuidGenerator = Generators.timeBasedEpochGenerator();

    private final Duration accessTokenLifetime;
    private final AccessTokenIssuer accessTokenIssuer;

    public TokenHandler(AuthorizationConfiguration config, AccessTokenIssuer accessTokenIssuer) {
        this.accessTokenIssuer = accessTokenIssuer;
        this.accessTokenLifetime = config.getAccessTokenLifetime();
    }

    public AccessTokenData processTokenRequest(TokenAuthSession session, SeedCredential seedCredential,
                                               JWKThumbprintConfirmation dpopJwkThumbprint, String refreshTokenId) {
        var accessToken = createAccessToken(seedCredential.reference(), seedCredential.subject(), session.getClientId(), session.getScope(), dpopJwkThumbprint, refreshTokenId);
        session.addGeneratedTokenProperties(seedCredential, accessToken.accessTokenID().toString());
        return accessToken;
    }

    public AccessTokenData processRefreshTokenRequest(RefreshTokenAuthSession session, SeedCredential seedCredential, String clientId,
                                                      JWKThumbprintConfirmation dpopThumbprintConfirmation, String refreshTokenId) {
        var accessToken = createAccessToken(seedCredential.reference(), seedCredential.subject(), clientId, session.getScope(), dpopThumbprintConfirmation, refreshTokenId);
        session.addGeneratedAccessTokenId(accessToken.accessTokenID().toString());
        return accessToken;
    }

    private AccessTokenData createAccessToken(String seedCredentialReferenceID, String seedCredentialReferenceSubject, String clientId,
                                              String scope, JWKThumbprintConfirmation dpopThumbprintConfirmation, String refreshTokenId) {
        var tokenID = uuidGenerator.generate();
        var token = accessTokenIssuer.buildAccessToken(
            tokenID,
            clientId,
            scope,
            dpopThumbprintConfirmation.getValue(),
            new SeedCredentialReference(seedCredentialReferenceID, seedCredentialReferenceSubject),
            refreshTokenId
        );
        return new AccessTokenData(tokenID, token, DPOP_SCHEME, accessTokenLifetime.toSeconds());
    }
}
