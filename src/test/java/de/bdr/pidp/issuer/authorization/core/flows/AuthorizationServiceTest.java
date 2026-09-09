/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.flows;

import com.nimbusds.oauth2.sdk.as.ReadOnlyAuthorizationServerMetadata;
import de.bdr.pidp.issuer.authorization.core.domain.FinishAuthRequest;
import de.bdr.pidp.issuer.authorization.core.domain.Requests;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSession;
import de.bdr.pidp.issuer.authorization.core.exception.FinishAuthException;
import de.bdr.pidp.issuer.authorization.core.exception.RequestUriExpiredException;
import de.bdr.pidp.issuer.authorization.core.particle.AuthorizationHandler;
import de.bdr.pidp.issuer.authorization.core.particle.ClientIdValidator;
import de.bdr.pidp.issuer.authorization.core.particle.FinishAuthorizationHandler;
import de.bdr.pidp.issuer.authorization.core.particle.RequestUtil;
import de.bdr.pidp.issuer.authorization.core.service.DPoPNonceService;
import de.bdr.pidp.issuer.authorization.port.out.AuthorizeDataPortOut;
import de.bdr.pidp.issuer.authorization.port.out.FinishAuthorizationDataPortOut;
import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.RandomUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.time.Instant;

import static de.bdr.pidp.issuer.authorization.config.MetaTestData.AUTH_METADATA;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class AuthorizationServiceTest {

    @Mock
    private ClientIdValidator clientIdValidator;
    @Mock
    private AuthorizeDataPortOut authorizeDataPortOut;
    @Mock
    private FinishAuthorizationDataPortOut finishAuthorizationDataPortOut;
    @Mock
    private AuthorizationHandler authorizationHandler;
    @Mock
    private DPoPNonceService dPoPNonceService;
    @Mock
    private FinishAuthorizationHandler finishAuthorizationHandler;
    @Spy
    private ReadOnlyAuthorizationServerMetadata metadata = AUTH_METADATA;

    @InjectMocks
    private AuthorizationService authService;

    @Test
    void processAuthRequest() {
        var request = RequestUtil.getAuthRequest();
        var clientIdString = request.getClientId();
        var requestUri = request.getRequestUri();

        // given - mock session
        var mockSession = mock(AuthSession.class);
        doReturn(mockSession).when(authorizeDataPortOut).loadByRequestUri(requestUri);
        doReturn(Requests.AUTHORIZATION_REQUEST).when(mockSession).getNextExpectedRequest();
        doReturn(clientIdString).when(mockSession).getClientId();
        doReturn(Instant.now().plusSeconds(30)).when(mockSession).getRequestUriExpirationTime();

        // when
        authService.processAuthRequest(request);

        // then
        verify(authorizeDataPortOut).loadByRequestUri(requestUri);
        verify(clientIdValidator).validateClientId(anyString(), anyString());
        verify(authorizationHandler).processAuthRequest(mockSession);
        verify(mockSession).setNextExpectedRequest(Requests.FINISH_AUTHORIZATION_REQUEST);
        verify(authorizeDataPortOut).save(mockSession);
    }

    @Test
    void processAuthRequestWithHandlerException() {
        var request = RequestUtil.getAuthRequest();
        var clientIdString = request.getClientId();
        var requestUri = request.getRequestUri();

        // given - override handlers
        Mockito.doThrow(new PidServerException("error"))
            .when(authorizationHandler)
            .processAuthRequest(any());

        // given - mock session
        var mockSession = mock(AuthSession.class);
        doReturn(mockSession).when(authorizeDataPortOut).loadByRequestUri(requestUri);
        doReturn(Requests.AUTHORIZATION_REQUEST).when(mockSession).getNextExpectedRequest();
        doReturn(clientIdString).when(mockSession).getClientId();
        doReturn(Instant.now().plusSeconds(30)).when(mockSession).getRequestUriExpirationTime();

        // when
        assertThatThrownBy(() -> authService.processAuthRequest(request))
            .isInstanceOf(PidServerException.class);

        // then
        verify(authorizeDataPortOut).loadByRequestUri(requestUri);
        verify(authorizeDataPortOut).save(mockSession);
    }

    @Test
    void processAuthRequestWithUnauthorizedExceptionWhenRequestUriExpired() {
        var request = RequestUtil.getAuthRequest();
        var requestUri = request.getRequestUri();

        // given - mock session
        var mockSession = mock(AuthSession.class);
        doReturn(mockSession).when(authorizeDataPortOut).loadByRequestUri(requestUri);
        doReturn(Instant.now().minusSeconds(30)).when(mockSession).getRequestUriExpirationTime();

        // when
        assertThatThrownBy(() -> authService.processAuthRequest(request))
            .isInstanceOf(RequestUriExpiredException.class)
            .hasMessage("Request uri expired");
    }

    @Test
    void processFaRequest() {
        var request = RequestUtil.getFinishAuthRequest();
        var issuerState = request.getIssuerState();

        // given - mock session
        var mockSession = mock(AuthSession.class);
        doReturn(mockSession).when(finishAuthorizationDataPortOut).loadByIssuerState(issuerState);
        doReturn(Requests.FINISH_AUTHORIZATION_REQUEST).when(mockSession).getNextExpectedRequest();
        doReturn(new Nonce(RandomUtil.randomString(), Duration.ofSeconds(30))).when(dPoPNonceService).provideAndSave(mockSession);

        // when
        authService.processFinishAuthRequest(request);

        // then
        verify(finishAuthorizationDataPortOut).loadByIssuerState(issuerState);
        verify(finishAuthorizationHandler).processFinishAuthRequest(request, mockSession);
        verify(finishAuthorizationDataPortOut).save(mockSession);
    }

    @Test
    void processFaRequestWithHandlerException() {
        var request = RequestUtil.getFinishAuthRequest();
        var issuerState = request.getIssuerState();

        // given - override handlers
        Mockito.doThrow(new PidServerException("error"))
            .when(finishAuthorizationHandler)
            .processFinishAuthRequest(any(FinishAuthRequest.class), any());

        // given - mock session
        var mockSession = mock(AuthSession.class);
        doReturn(mockSession).when(finishAuthorizationDataPortOut).loadByIssuerState(issuerState);
        doReturn(Requests.FINISH_AUTHORIZATION_REQUEST).when(mockSession).getNextExpectedRequest();

        // when
        assertThatThrownBy(() -> authService.processFinishAuthRequest(request))
            .isInstanceOf(FinishAuthException.class);

        // then
        verify(finishAuthorizationDataPortOut).loadByIssuerState(issuerState);
        verify(finishAuthorizationDataPortOut).save(mockSession);
        verify(mockSession).getRedirectUri();
        verify(mockSession).getState();
        verify(finishAuthorizationHandler).processFinishAuthRequest(request, mockSession);
    }
}
