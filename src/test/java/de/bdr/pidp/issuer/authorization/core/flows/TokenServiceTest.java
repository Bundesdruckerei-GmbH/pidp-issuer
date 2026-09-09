/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.flows;

import de.bdr.pidp.issuer.authorization.core.domain.RefreshTokenData;
import de.bdr.pidp.issuer.authorization.core.domain.Requests;
import de.bdr.pidp.issuer.authorization.core.domain.SeedCredential;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSession;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidGrantException;
import de.bdr.pidp.issuer.authorization.core.exception.SessionNotFoundException;
import de.bdr.pidp.issuer.authorization.core.particle.ClientAttestationValidator;
import de.bdr.pidp.issuer.authorization.core.particle.ClientIdValidator;
import de.bdr.pidp.issuer.authorization.core.particle.PKCEValidator;
import de.bdr.pidp.issuer.authorization.core.particle.RedirectUriValidator;
import de.bdr.pidp.issuer.authorization.core.particle.RefreshTokenIssuanceHandler;
import de.bdr.pidp.issuer.authorization.core.particle.RefreshTokenValidationHandler;
import de.bdr.pidp.issuer.authorization.core.particle.RequestUtil;
import de.bdr.pidp.issuer.authorization.core.particle.ScopeValidator;
import de.bdr.pidp.issuer.authorization.core.particle.TokenHandler;
import de.bdr.pidp.issuer.authorization.core.particle.dpop.DPoPValidator;
import de.bdr.pidp.issuer.authorization.core.service.DPoPNonceService;
import de.bdr.pidp.issuer.authorization.port.out.IdentificationDataPortOut;
import de.bdr.pidp.issuer.authorization.port.out.RefreshTokenDataPortOut;
import de.bdr.pidp.issuer.authorization.port.out.TokenDataPortOut;
import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.RandomUtil;
import de.bdr.pidp.issuer.testdata.TestRefreshTokenIssuer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class TokenServiceTest {
    @Mock
    private PKCEValidator pkceValidator;
    @Mock
    private ClientIdValidator clientIdValidator;
    @Mock
    private RedirectUriValidator redirectUriValidator;
    @Mock
    private ScopeValidator scopeValidator;
    @Mock
    private ClientAttestationValidator clientAttestationValidator;
    @Mock
    private TokenDataPortOut tokenDataPortOut;
    @Mock
    private RefreshTokenDataPortOut refreshTokenDataPortOut;
    @Mock
    private DPoPValidator dPoPValidator;
    @Mock
    private IdentificationDataPortOut identificationDataPortOut;
    @Mock
    private DPoPNonceService dPoPNonceService;
    @Mock
    private TokenHandler tokenHandler;
    @Mock
    private RefreshTokenIssuanceHandler refreshTokenIssuanceHandler;
    @Mock
    private RefreshTokenValidationHandler refreshTokenValidationHandler;

    @InjectMocks
    private TokenService tokenService;

    @Test
    void processTokenRequest() {
        // given - mock session
        var mockSession = Mockito.mock(AuthSession.class);
        doReturn(mockSession).when(tokenDataPortOut).loadByAuthorizationCode(anyString());
        doReturn(Requests.TOKEN_REQUEST).when(mockSession).getNextExpectedRequest();
        doReturn(Instant.now().plusSeconds(30)).when(mockSession).getAuthorizationCodeExpirationTime();
        doReturn(new Nonce(RandomUtil.randomString(), Duration.ofSeconds(30))).when(dPoPNonceService).provideAndSave(mockSession);
        doReturn(new RefreshTokenData(TestRefreshTokenIssuer.buildRefreshToken(), Instant.now().toEpochMilli())).when(refreshTokenIssuanceHandler).processTokenRequest(any(), any(), any(), any(), any());

        // when
        var request = RequestUtil.getTokenRequest(null);
        tokenService.processTokenRequest(request);

        // then
        verify(tokenDataPortOut).loadByAuthorizationCode(request.getAuthCode());
        verify(pkceValidator).validateCodeVerifier(any(), any(), any());
        verify(redirectUriValidator).validateRedirectUri(any(), any());
        verify(tokenDataPortOut).save(mockSession);
        verify(tokenHandler).processTokenRequest(eq(mockSession), any(), any(), any());
    }

    @Test
    void processTokenRequestWithHandlerException() {
        // given - override handlers
        doThrow(new PidServerException("error"))
            .when(tokenHandler)
            .processTokenRequest(any(AuthSession.class), any(), any(), any());

        // given - mock session
        var mockSession = Mockito.mock(AuthSession.class);
        doReturn(mockSession).when(tokenDataPortOut).loadByAuthorizationCode(anyString());
        doReturn(Requests.TOKEN_REQUEST).when(mockSession).getNextExpectedRequest();
        doReturn(Instant.now().plusSeconds(30)).when(mockSession).getAuthorizationCodeExpirationTime();
        doReturn(new Nonce(RandomUtil.randomString(), Duration.ofSeconds(30))).when(dPoPNonceService).provideAndSave(mockSession);
        doReturn(new RefreshTokenData(TestRefreshTokenIssuer.buildRefreshToken(), Instant.now().toEpochMilli())).when(refreshTokenIssuanceHandler).processTokenRequest(any(), any(), any(), any(), any());

        // when
        var request = RequestUtil.getTokenRequest(null);
        assertThatThrownBy(() -> tokenService.processTokenRequest(request))
            .isInstanceOf(PidServerException.class);

        // then
        verify(tokenDataPortOut).loadByAuthorizationCode(request.getAuthCode());
        verify(tokenDataPortOut).save(mockSession);
    }

    @Test
    void processTokenRequestWithInvalidGrantWhenAuthorizationCodeExpired() {
        // given - mock session
        var mockSession = Mockito.mock(AuthSession.class);
        doReturn(mockSession).when(tokenDataPortOut).loadByAuthorizationCode(anyString());
        doReturn(Instant.now().minusSeconds(30)).when(mockSession).getAuthorizationCodeExpirationTime();

        // when
        var request = RequestUtil.getTokenRequest(null);
        assertThatThrownBy(() -> tokenService.processTokenRequest(request))
            .isInstanceOf(InvalidGrantException.class)
            .hasMessage("Session is expired");
    }

    @Test
    void processRefreshTokenRequest() {
        var request = RequestUtil.getRefreshTokenRequest();
        var refreshToken = request.getRefreshToken();

        // given - mock session
        var mockSession = Mockito.mock(AuthSession.class);
        doReturn(mockSession).when(refreshTokenDataPortOut).loadByRefreshToken(refreshToken);
        doReturn(new Nonce(RandomUtil.randomString(), Duration.ofSeconds(30))).when(dPoPNonceService).provideAndSave(mockSession);
        doReturn(new SeedCredential("seedCredential", "reference", "sub", Instant.now().plusSeconds(30)))
            .when(refreshTokenValidationHandler).processRefreshTokenRequest(any(), any(), anyString(), any());

        // when
        tokenService.processRefreshTokenRequest(request);

        // then
        verify(refreshTokenDataPortOut).loadByRefreshToken(refreshToken);
        verify(refreshTokenDataPortOut).save(mockSession);
        verify(clientIdValidator).validateClientId(anyString());
        verify(scopeValidator).validateScope(anyString());
        verify(clientAttestationValidator).validateClientAttestation(any(), any(), anyString());
        verify(dPoPValidator).validateDPoPProof(any(), any(), eq(false), any());
        verify(dPoPNonceService).provideAndSave(mockSession);
        verify(refreshTokenValidationHandler).processRefreshTokenRequest(any(), any(), anyString(), any());
        verify(tokenHandler).processRefreshTokenRequest(any(AuthSession.class), any(), anyString(), any(), any());
        verify(mockSession).setNextExpectedRequest(Requests.CREDENTIAL_REQUEST);
    }

    @Test
    void processRefreshTokenRequestInit() {
        var request = RequestUtil.getRefreshTokenRequest();
        var refreshToken = request.getRefreshToken();

        // given - mock session
        var mockSession = Mockito.mock(AuthSession.class);
        doThrow(SessionNotFoundException.class).when(refreshTokenDataPortOut).loadByRefreshToken(refreshToken);
        doReturn(mockSession).when(refreshTokenDataPortOut).initByRefreshToken(refreshToken);
        doReturn(new Nonce(RandomUtil.randomString(), Duration.ofSeconds(30))).when(dPoPNonceService).provideAndSave(mockSession);
        doReturn(new SeedCredential("seedCredential", "reference", "sub", Instant.now().plusSeconds(30)))
            .when(refreshTokenValidationHandler).processRefreshTokenRequest(any(), any(), anyString(), any());

        // when
        tokenService.processRefreshTokenRequest(request);

        // then
        verify(refreshTokenDataPortOut).loadByRefreshToken(refreshToken);
        verify(refreshTokenDataPortOut).initByRefreshToken(refreshToken);
        verify(refreshTokenDataPortOut).save(mockSession);
        verify(clientIdValidator).validateClientId(anyString());
        verify(scopeValidator).validateScope(anyString());
        verify(clientAttestationValidator).validateClientAttestation(any(), any(), anyString());
        verify(dPoPValidator).validateDPoPProof(any(), any(), eq(false), any());
        verify(dPoPNonceService).provideAndSave(mockSession);
        verify(refreshTokenValidationHandler).processRefreshTokenRequest(any(), any(), anyString(), any());
        verify(tokenHandler).processRefreshTokenRequest(any(AuthSession.class), any(), anyString(), any(), any());
        verify(mockSession).setNextExpectedRequest(Requests.CREDENTIAL_REQUEST);
    }

    @Test
    void processRefreshTokenRequestWithoutScope() {
        var params = RequestUtil.getValidRefreshTokenRequestParams();
        params.remove("scope");
        var request = RequestUtil.getRefreshTokenRequest(null, params);
        var refreshToken = request.getRefreshToken();

        // given - mock session
        var mockSession = Mockito.mock(AuthSession.class);
        doReturn(mockSession).when(refreshTokenDataPortOut).loadByRefreshToken(refreshToken);
        doReturn(new Nonce(RandomUtil.randomString(), Duration.ofSeconds(30))).when(dPoPNonceService).provideAndSave(mockSession);
        doReturn(new SeedCredential("seedCredential", "reference", "sub", Instant.now().plusSeconds(30)))
            .when(refreshTokenValidationHandler).processRefreshTokenRequest(any(), any(), anyString(), any());

        // when
        tokenService.processRefreshTokenRequest(request);

        // then
        verify(scopeValidator, Mockito.never()).validateScope(anyString());
    }

    @Test
    void processRefreshTokenRequestWithHandlerException() {
        var request = RequestUtil.getRefreshTokenRequest();
        var refreshToken = request.getRefreshToken();

        // given - override handlers
        doThrow(new PidServerException("error"))
            .when(tokenHandler)
            .processRefreshTokenRequest(any(), any(), anyString(), any(), any());

        // given - mock session
        var mockSession = Mockito.mock(AuthSession.class);
        doReturn(mockSession).when(refreshTokenDataPortOut).loadByRefreshToken(refreshToken);
        doReturn(new Nonce(RandomUtil.randomString(), Duration.ofSeconds(30))).when(dPoPNonceService).provideAndSave(mockSession);
        doReturn(new SeedCredential("seedCredential", "reference", "sub", Instant.now().plusSeconds(30)))
            .when(refreshTokenValidationHandler).processRefreshTokenRequest(any(), any(), anyString(), any());

        // when
        assertThatThrownBy(() -> tokenService.processRefreshTokenRequest(request))
            .isInstanceOf(PidServerException.class);

        // then
        verify(refreshTokenDataPortOut).loadByRefreshToken(refreshToken);
        verify(refreshTokenDataPortOut).save(mockSession);
    }
}
