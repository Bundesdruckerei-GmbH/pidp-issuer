/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.out.persistence;

import com.nimbusds.jwt.SignedJWT;
import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.authorization.core.domain.Requests;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSession;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSessionView;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthorizeAuthSession;
import de.bdr.pidp.issuer.authorization.core.domain.data.FinishAuthorizationAuthSession;
import de.bdr.pidp.issuer.authorization.core.domain.data.ParAuthSession;
import de.bdr.pidp.issuer.authorization.core.domain.data.RefreshTokenAuthSession;
import de.bdr.pidp.issuer.authorization.core.domain.data.SeedCredentialDataAuthSession;
import de.bdr.pidp.issuer.authorization.core.domain.data.TokenAuthSession;
import de.bdr.pidp.issuer.authorization.core.domain.data.TokenIntrospectAuthSession;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import de.bdr.pidp.issuer.authorization.core.exception.SessionNotFoundException;
import de.bdr.pidp.issuer.authorization.port.out.AuthorizationHousekeepingPortOut;
import de.bdr.pidp.issuer.authorization.port.out.AuthorizeDataPortOut;
import de.bdr.pidp.issuer.authorization.port.out.FinishAuthorizationDataPortOut;
import de.bdr.pidp.issuer.authorization.port.out.ParDataPortOut;
import de.bdr.pidp.issuer.authorization.port.out.RefreshTokenDataPortOut;
import de.bdr.pidp.issuer.authorization.port.out.SeedCredentialDataPortOut;
import de.bdr.pidp.issuer.authorization.port.out.TokenDataPortOut;
import de.bdr.pidp.issuer.authorization.port.out.TokenIntrospectDataPortOut;
import org.jspecify.annotations.NullMarked;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static de.bdr.pidp.issuer.authorization.config.MdcKeys.MDC_AUTH_SESSION_ID;
import static de.bdr.pidp.issuer.authorization.config.MdcKeys.MDC_CLIENT_ID;

@NullMarked
@Component
class AuthSessionDataPostgresAdapter implements ParDataPortOut, AuthorizeDataPortOut,
    FinishAuthorizationDataPortOut, TokenDataPortOut, RefreshTokenDataPortOut, TokenIntrospectDataPortOut,
    SeedCredentialDataPortOut, AuthorizationHousekeepingPortOut {

    private final AuthSessionRepository authSessionRepository;
    private final Duration sessionExpirationTime;

    public AuthSessionDataPostgresAdapter(AuthSessionRepository authSessionRepository, AuthorizationConfiguration config) {
        this.authSessionRepository = authSessionRepository;
        this.sessionExpirationTime = config.getSessionExpirationTime();
    }

    public ParAuthSession init() {
        var entity = new AuthSessionEntity();
        entity.setNextExpectedRequest(Requests.PUSHED_AUTHORIZATION_REQUEST);
        setExpirationTime(entity, sessionExpirationTime);
        var saved = authSessionRepository.save(entity);
        prepareMdc(saved);
        return AuthSessionMapper.map(saved);
    }

    @Override
    public AuthorizeAuthSession loadByRequestUri(String requestUri) {
        AuthSessionEntity authSessionEntity = authSessionRepository.findFirstByRequestUri(requestUri)
            .orElseThrow(SessionNotFoundException::new);
        prepareMdc(authSessionEntity);
        return AuthSessionMapper.map(authSessionEntity);
    }

    @Override
    public FinishAuthorizationAuthSession loadByIssuerState(String issuerState) {
        AuthSessionEntity authSessionEntity = authSessionRepository.findFirstByIssuerState(issuerState)
            .orElseThrow(SessionNotFoundException::new);
        prepareMdc(authSessionEntity);
        return AuthSessionMapper.map(authSessionEntity);
    }

    @Override
    public TokenAuthSession loadByAuthorizationCode(String authorizationCode) {
        AuthSessionEntity authSessionEntity = authSessionRepository.findFirstByAuthorizationCode(authorizationCode)
            .orElseThrow(SessionNotFoundException::new);
        prepareMdc(authSessionEntity);
        return AuthSessionMapper.map(authSessionEntity);
    }

    @Override
    public TokenIntrospectAuthSession loadByAccessTokenID(String accessTokenID) {
        AuthSessionEntity authSessionEntity = authSessionRepository.findFirstByAccessTokenID(accessTokenID)
            .orElseThrow(SessionNotFoundException::new);
        prepareMdc(authSessionEntity);
        return AuthSessionMapper.map(authSessionEntity);
    }

    @Override
    public SeedCredentialDataAuthSession loadBySeedCredentialRef(String seedCredentialRef) {
        AuthSessionEntity authSessionEntity = authSessionRepository.findFirstBySeedCredentialRef(seedCredentialRef)
            .orElseThrow(SessionNotFoundException::new);
        prepareMdc(authSessionEntity);
        return AuthSessionMapper.map(authSessionEntity);
    }

    @Override
    public RefreshTokenAuthSession initByRefreshToken(SignedJWT refreshToken) {
        var entity = new AuthSessionEntity();
        var jti = getRefreshTokenJti(refreshToken);
        entity.setNextExpectedRequest(Requests.TOKEN_REQUEST);
        entity.setRefreshTokenID(jti);
        setExpirationTime(entity, sessionExpirationTime);
        var saved = authSessionRepository.save(entity);
        prepareMdc(saved);
        return AuthSessionMapper.map(saved);
    }

    @Override
    public RefreshTokenAuthSession loadByRefreshToken(SignedJWT refreshToken) {
        var jti = getRefreshTokenJti(refreshToken);
        AuthSessionEntity authSessionEntity = authSessionRepository.findFirstByRefreshTokenID(jti)
            .orElseThrow(SessionNotFoundException::new);
        prepareMdc(authSessionEntity);
        return AuthSessionMapper.map(authSessionEntity);
    }

    @Transactional
    @Override
    public void save(AuthSessionView authSessionView) {
        if (authSessionView instanceof AuthSession authSession) {
            var entity = authSessionRepository.getReferenceById(authSession.getSessionId());
            setAllFields(authSession, entity);
            setExpirationTime(entity, sessionExpirationTime);
        }
    }

    @Transactional
    @Override
    public int deleteExpiredSessions() {
        return authSessionRepository.deleteAllByExpiresBefore(Instant.now());
    }

    private void setAllFields(AuthSession source, AuthSessionEntity target) {
        // Tokens
        target.setAccessTokenID(source.getAccessTokenID());

        // Authorization code
        target.setAuthorizationCode(source.getAuthorizationCode());
        target.setAuthorizationCodeExpirationTime(source.getAuthorizationCodeExpirationTime());

        // Client Attestation status list ref
        target.setClientAttestationStatusListRefURI(source.getClientAttestationStatusListRefURI());
        target.setClientAttestationStatusListRefIndex(source.getClientAttestationStatusListRefIndex());

        // Client identifiers
        target.setClientId(source.getClientId());

        // PKCE data
        target.setCodeChallenge(source.getCodeChallenge());
        target.setCodeChallengeMethod(source.getCodeChallengeMethod());

        // DPoP related data
        target.setDpopNonce(source.getDpopNonce());
        target.setDpopNonceExpirationTime(source.getDpopNonceExpirationTime());

        // Identification token data
        target.setSeedCredentialData(source.getSeedCredentialData());
        target.setSeedCredentialRef(source.getSeedCredentialRef());
        target.setSeedCredentialSub(source.getSeedCredentialSub());
        target.setSeedCredentialExpirationTime(source.getSeedCredentialExpirationTime());

        // Miscellaneous OAuth parameters
        target.setIssuerState(source.getIssuerState());
        target.setRedirectUri(source.getRedirectUri());

        // Request‑URI handling
        target.setRequestUri(source.getRequestUri());
        target.setRequestUriExpirationTime(source.getRequestUriExpirationTime());

        // RefreshTokenID
        target.setRefreshTokenID(source.getRefreshTokenID());

        // Scoping & state
        target.setScope(source.getScope());
        target.setState(source.getState());

        target.setNextExpectedRequest(source.getNextExpectedRequest());
    }

    private void setExpirationTime(AuthSessionEntity entity, Duration sessionExpirationTime) {
        /*
        Postgress timestamp contains only microseconds and no nanoseconds
         */
        entity.setExpires(Instant.now().plus(sessionExpirationTime).truncatedTo(ChronoUnit.MICROS));
    }

    private static String getRefreshTokenJti(SignedJWT refreshToken) {
        try {
            return refreshToken.getJWTClaimsSet().getJWTID();
        } catch (ParseException e) {
            throw new InvalidRequestException("Refresh token invalid", e);
        }
    }

    private static void prepareMdc(AuthSessionEntity result) {
        MDC.put(MDC_AUTH_SESSION_ID, String.valueOf(result.getSessionId()));
        if (result.getClientId() != null) {
            MDC.put(MDC_CLIENT_ID, result.getClientId());
        }
    }
}
