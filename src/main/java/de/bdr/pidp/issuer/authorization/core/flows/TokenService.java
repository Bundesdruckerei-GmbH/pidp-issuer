/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.flows;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import de.bdr.pidp.issuer.authorization.core.domain.AccessTokenData;
import de.bdr.pidp.issuer.authorization.core.domain.RefreshTokenData;
import de.bdr.pidp.issuer.authorization.core.domain.RefreshTokenRequest;
import de.bdr.pidp.issuer.authorization.core.domain.RefreshTokenResult;
import de.bdr.pidp.issuer.authorization.core.domain.Requests;
import de.bdr.pidp.issuer.authorization.core.domain.SeedCredential;
import de.bdr.pidp.issuer.authorization.core.domain.TokenRequest;
import de.bdr.pidp.issuer.authorization.core.domain.TokenResult;
import de.bdr.pidp.issuer.authorization.core.domain.data.RefreshTokenAuthSession;
import de.bdr.pidp.issuer.authorization.core.domain.data.TokenAuthSession;
import de.bdr.pidp.issuer.authorization.core.exception.DPoPValidationException;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidGrantException;
import de.bdr.pidp.issuer.authorization.core.exception.SessionNotFoundException;
import de.bdr.pidp.issuer.authorization.core.particle.ClientAttestationValidator;
import de.bdr.pidp.issuer.authorization.core.particle.ClientIdValidator;
import de.bdr.pidp.issuer.authorization.core.particle.PKCEValidator;
import de.bdr.pidp.issuer.authorization.core.particle.RedirectUriValidator;
import de.bdr.pidp.issuer.authorization.core.particle.RefreshTokenIssuanceHandler;
import de.bdr.pidp.issuer.authorization.core.particle.RefreshTokenValidationHandler;
import de.bdr.pidp.issuer.authorization.core.particle.RequestOrderValidator;
import de.bdr.pidp.issuer.authorization.core.particle.ScopeValidator;
import de.bdr.pidp.issuer.authorization.core.particle.TokenHandler;
import de.bdr.pidp.issuer.authorization.core.particle.dpop.DPoPValidator;
import de.bdr.pidp.issuer.authorization.core.service.DPoPNonceService;
import de.bdr.pidp.issuer.authorization.port.out.IdentificationDataPortOut;
import de.bdr.pidp.issuer.authorization.port.out.RefreshTokenDataPortOut;
import de.bdr.pidp.issuer.authorization.port.out.TokenDataPortOut;
import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.base.PidServerException;
import lombok.RequiredArgsConstructor;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Instant;

import static de.bdr.pidp.issuer.authorization.config.MdcKeys.MDC_CLIENT_ID;
import static de.bdr.pidp.issuer.base.PidDataConst.DPOP_NONCE_HEADER;

@RequiredArgsConstructor
@Service
public class TokenService {
    private final PKCEValidator pkceValidator;
    private final ClientIdValidator clientIdValidator;
    private final RedirectUriValidator redirectUriValidator;
    private final ScopeValidator scopeValidator;
    private final ClientAttestationValidator clientAttestationValidator;
    private final TokenDataPortOut tokenDataPortOut;
    private final RefreshTokenDataPortOut refreshTokenDataPortOut;
    private final DPoPValidator dPoPValidator;
    private final IdentificationDataPortOut identificationProvider;
    private final DPoPNonceService dPoPNonceService;
    private final TokenHandler tokenHandler;
    private final RefreshTokenIssuanceHandler refreshTokenIssuanceHandler;
    private final RefreshTokenValidationHandler refreshTokenValidationHandler;

    public TokenResult processTokenRequest(TokenRequest request) {
        var authCode = request.getAuthCode();
        var codeVerifier = request.getCodeVerifier();
        var redirectUriFromRequest = request.getRedirectUri();

        TokenAuthSession tokenAuthSession = tokenDataPortOut.loadByAuthorizationCode(authCode);
        if (tokenAuthSession.getAuthorizationCodeExpirationTime().isBefore(Instant.now())) {
            throw new InvalidGrantException("Session is expired");
        }

        var codeChallengeMethod = tokenAuthSession.getCodeChallengeMethod();
        var codeChallenge = tokenAuthSession.getCodeChallenge();
        var redirectUriFromSession = tokenAuthSession.getRedirectUri();

        pkceValidator.validateCodeVerifier(codeVerifier, codeChallenge, codeChallengeMethod);
        redirectUriValidator.validateRedirectUri(redirectUriFromRequest, redirectUriFromSession);

        TokenResult tokenResult;
        try {
            RequestOrderValidator.validateRequest(tokenAuthSession, Requests.TOKEN_REQUEST);
            JWKThumbprintConfirmation dpopJwkThumbprint = dPoPValidator.validateDPoPProof(request.getDpopHeaders(), tokenAuthSession, true, tokenAuthSession.getClientId());
            Nonce nonce = dPoPNonceService.provideAndSave(tokenAuthSession);
            SeedCredential seedCredential = identificationProvider.collectEncryptedIdentification(tokenAuthSession.getIssuerState());
            RefreshTokenData refreshTokenData = refreshTokenIssuanceHandler.processTokenRequest(tokenAuthSession.getClientId(),
                tokenAuthSession.getScope(), dpopJwkThumbprint, seedCredential, tokenAuthSession.getClientAttestationStatusListRef());
            String refreshTokenId = getRefreshTokenId(refreshTokenData.refreshToken());
            AccessTokenData accessTokenData =
                tokenHandler.processTokenRequest(tokenAuthSession, seedCredential, dpopJwkThumbprint, refreshTokenId);

            tokenResult = new TokenResult(accessTokenData, refreshTokenData, nonce);
            tokenAuthSession.setNextExpectedRequest(Requests.CREDENTIAL_REQUEST);
        } catch (DPoPValidationException e) {
            Nonce nonce = dPoPNonceService.provideAndSave(tokenAuthSession);
            e.addHeader(DPOP_NONCE_HEADER, nonce.nonce());
            throw e;
        } finally {
            tokenDataPortOut.save(tokenAuthSession);
        }
        return tokenResult;
    }

    public RefreshTokenResult processRefreshTokenRequest(RefreshTokenRequest request) {
        String clientId = request.getClientId();
        MDC.put(MDC_CLIENT_ID, clientId);

        clientIdValidator.validateClientId(clientId);

        var scope = request.getScope();
        if (scope != null) {
            scopeValidator.validateScope(scope);
        }

        clientAttestationValidator.validateClientAttestation(request.getAttestation(), request.getAttestationPoP(), clientId);

        var refreshToken = request.getRefreshToken();

        RefreshTokenAuthSession refreshTokenAuthSession;
        try {
            refreshTokenAuthSession = refreshTokenDataPortOut.loadByRefreshToken(refreshToken);
        } catch (SessionNotFoundException _) {
            refreshTokenAuthSession = refreshTokenDataPortOut.initByRefreshToken(refreshToken);
        }

        RefreshTokenResult refreshTokenResult;
        try {
            JWKThumbprintConfirmation dpopJwkThumbprint = dPoPValidator.validateDPoPProof(request.getDpopHeaders(), refreshTokenAuthSession, false, clientId);
            var nonce = dPoPNonceService.provideAndSave(refreshTokenAuthSession);
            SeedCredential seedCredential = refreshTokenValidationHandler.processRefreshTokenRequest(request, refreshTokenAuthSession, clientId, dpopJwkThumbprint);
            String refreshTokenId = getRefreshTokenId(refreshToken);
            AccessTokenData accessTokenData =
                tokenHandler.processRefreshTokenRequest(refreshTokenAuthSession, seedCredential, clientId, dpopJwkThumbprint, refreshTokenId);

            refreshTokenResult = new RefreshTokenResult(accessTokenData, nonce);
            refreshTokenAuthSession.setNextExpectedRequest(Requests.CREDENTIAL_REQUEST);
        } catch (DPoPValidationException e) {
            Nonce nonce = dPoPNonceService.provideAndSave(refreshTokenAuthSession);
            e.addHeader(DPOP_NONCE_HEADER, nonce.nonce());
            throw e;
        } finally {
            refreshTokenDataPortOut.save(refreshTokenAuthSession);
        }
        return refreshTokenResult;
    }

    private String getRefreshTokenId(SignedJWT refreshToken) {
        try {
            return refreshToken.getJWTClaimsSet().getJWTID();
        } catch (ParseException e) {
            // will not be parsed, since it was just created, this exception shall not occur
            throw new PidServerException("Could not access claims set of generated refresh_token", e);
        }
    }
}
