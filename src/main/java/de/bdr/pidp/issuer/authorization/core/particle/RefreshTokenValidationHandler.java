/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import de.bdr.pidp.issuer.authorization.core.domain.RefreshTokenRequest;
import de.bdr.pidp.issuer.authorization.core.domain.SeedCredential;
import de.bdr.pidp.issuer.authorization.core.domain.data.RefreshTokenAuthSession;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidGrantException;
import de.bdr.pidp.issuer.authorization.core.particle.refreshtoken.RefreshTokenValidator;
import de.bdr.pidp.issuer.authorization.port.out.IdentificationDataPortOut;
import de.bdr.pidp.issuer.authorization.port.out.InvalidSeedCredentialException;
import de.bdr.pidp.issuer.authorization.port.out.RefreshTokenLifecyclePortOut;
import de.bdr.pidp.issuer.base.constants.RefreshTokenClaims;
import de.bdr.pidp.issuer.base.logging.LogType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.text.ParseException;

@Slf4j
@Component
@RequiredArgsConstructor
public class RefreshTokenValidationHandler {

    private final IdentificationDataPortOut identificationProvider;
    private final RefreshTokenValidator refreshTokenValidator;
    private final RefreshTokenLifecyclePortOut refreshTokenLifecyclePort;

    public SeedCredential processRefreshTokenRequest(RefreshTokenRequest request, RefreshTokenAuthSession session,
                                                     String clientId, JWKThumbprintConfirmation dpopJwkThumbprint) {
        var refreshToken = request.getRefreshToken();
        var requestScope = new Scope(Scope.parse(request.getScope()));

        var claims = refreshTokenValidator.validate(
            refreshToken,
            clientId,
            dpopJwkThumbprint.getValue(),
            requestScope);

        if (!refreshTokenLifecyclePort.isTokenValid(claims.getJWTID())) {
            try (var _ = LogType.mdcContext(LogType.Value.SECURITY)) {
                log.warn("Refresh token lifecycle status is not valid");
            }
            throw new InvalidGrantException("Refresh token lifecycle status is invalid");
        }

        String seedCredentialData;
        Scope scope;
        try {
            seedCredentialData = claims.getStringClaim(RefreshTokenClaims.SEED_CREDENTIAL);
            scope = requestScope.isEmpty() ? Scope.parse(claims.getStringClaim(RefreshTokenClaims.SCOPE)) : requestScope;
        } catch (ParseException e) {
            throw new IllegalStateException("Validated claims could not be parsed", e);
        }

        try {
            SeedCredential seedCredential = identificationProvider.verifySeedCredential(seedCredentialData);

            session.addValidatedRefreshTokenRequestParams(clientId, scope.toString(), seedCredential);
            return seedCredential;
        } catch (InvalidSeedCredentialException e) {
            throw new InvalidGrantException("Seed credential at the refresh token is invalid", e);
        }
    }
}
