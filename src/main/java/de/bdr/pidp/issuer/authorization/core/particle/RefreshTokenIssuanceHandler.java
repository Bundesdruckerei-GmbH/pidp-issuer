/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import de.bdr.pidp.issuer.authorization.core.domain.RefreshTokenData;
import de.bdr.pidp.issuer.authorization.core.domain.SeedCredential;
import de.bdr.pidp.issuer.authorization.core.service.RefreshTokenIssuer;
import de.bdr.pidp.issuer.authorization.port.out.RefreshTokenLifecyclePortOut;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.jwt.StatusListRef;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;

@Component
public class RefreshTokenIssuanceHandler {
    private final RefreshTokenIssuer refreshTokenIssuer;
    private final RefreshTokenLifecyclePortOut refreshTokenLifecyclePort;

    public RefreshTokenIssuanceHandler(RefreshTokenIssuer refreshTokenIssuer, RefreshTokenLifecyclePortOut refreshTokenLifecyclePort) {
        this.refreshTokenIssuer = refreshTokenIssuer;
        this.refreshTokenLifecyclePort = refreshTokenLifecyclePort;
    }

    public RefreshTokenData processTokenRequest(String clientId, String scope, JWKThumbprintConfirmation dpopJwkThumbprint,
                                                SeedCredential seedCredential, @Nullable StatusListRef clientAttestationStatusListRef) {
        var token = refreshTokenIssuer.buildRefreshToken(
            clientId,
            scope,
            dpopJwkThumbprint.getValue(),
            seedCredential
        );

        registerTokenLifecycle(token, clientAttestationStatusListRef);

        var timeout = timeoutInSeconds(token);
        return new RefreshTokenData(token, timeout);
    }

    private void registerTokenLifecycle(SignedJWT token, @Nullable StatusListRef statusListRef) {
        try {
            var claims = token.getJWTClaimsSet();
            refreshTokenLifecyclePort.registerToken(claims.getJWTID(), claims.getSubject(), claims.getExpirationTime().toInstant(), statusListRef);
        } catch (ParseException e) {
            // will not be parsed, since it was just created, this exception shall not occur
            throw new PidServerException("Could not access claims set of generated refresh_token", e);
        }
    }

    private long timeoutInSeconds(SignedJWT refreshToken) {
        var now =  Instant.now();
        Instant exp;
        try {
            exp = refreshToken.getJWTClaimsSet().getExpirationTime().toInstant();
        } catch (ParseException e) {
            // will not be parsed, since it was just created, this exception shall not occur
            throw new PidServerException("Could not access claims set of generated refresh_token", e);
        }

        return Duration.between(now, exp).toSeconds();
    }
}
