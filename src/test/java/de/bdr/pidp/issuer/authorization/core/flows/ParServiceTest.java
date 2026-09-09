/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.flows;

import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import de.bdr.pidp.issuer.authorization.core.domain.ParRequest;
import de.bdr.pidp.issuer.authorization.core.domain.Requests;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSession;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import de.bdr.pidp.issuer.authorization.core.particle.ClientAttestationValidator;
import de.bdr.pidp.issuer.authorization.core.particle.ClientIdValidator;
import de.bdr.pidp.issuer.authorization.core.particle.PKCEValidator;
import de.bdr.pidp.issuer.authorization.core.particle.ParHandler;
import de.bdr.pidp.issuer.authorization.core.particle.RedirectUriValidator;
import de.bdr.pidp.issuer.authorization.core.particle.RequestUtil;
import de.bdr.pidp.issuer.authorization.core.particle.ScopeValidator;
import de.bdr.pidp.issuer.authorization.core.particle.StateValidator;
import de.bdr.pidp.issuer.authorization.port.out.ParDataPortOut;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class ParServiceTest {
    @Mock
    private PKCEValidator pkceValidator;
    @Mock
    private ClientIdValidator clientIdValidator;
    @Mock
    private RedirectUriValidator redirectUriValidator;
    @Mock
    private ScopeValidator scopeValidator;
    @Mock
    private StateValidator stateValidator;
    @Mock
    private ClientAttestationValidator clientAttestationValidator;
    @Mock
    private ParHandler parHandler;
    @Mock
    private ParDataPortOut parDataPortOut;

    @InjectMocks
    private ParService parService;

    @Test
    void processRequest() {
        // given - override validator
        doReturn(new ClientAttestationValidator.AttestationValues(TestUtils.CLIENT_PUBLIC_KEY, TestUtils.CLIENT_ATTESTATION_STATUS_LIST_REF))
            .when(clientAttestationValidator).validateClientAttestation(any(), any(), anyString());

        // given - mock session
        var mockSession = Mockito.mock(AuthSession.class);
        doReturn(mockSession).when(parDataPortOut).init();
        doReturn(Requests.PUSHED_AUTHORIZATION_REQUEST).when(mockSession).getNextExpectedRequest();

        // when
        var request = RequestUtil.getParRequest();
        parService.processPushedAuthRequest(request);

        // then
        verify(parDataPortOut).init();
        verify(parDataPortOut).save(mockSession);
        verify(pkceValidator).validateCodeChallenge(anyString(), any(CodeChallengeMethod.class));
        verify(clientIdValidator).validateClientId(anyString());
        verify(redirectUriValidator).validateRedirectUri(anyString());
        verify(scopeValidator).validateScope(anyString());
        verify(stateValidator).validateState(anyString());
        verify(clientAttestationValidator).validateClientAttestation(any(), any(), any());
        verify(parHandler).processPushedAuthRequest(request, mockSession);
    }

    @Test
    void processRequestWithValidatorException() {
        // given - override a validator
        doThrow(new InvalidRequestException("error"))
            .when(clientIdValidator)
            .validateClientId(anyString());

        // when
        var request = RequestUtil.getParRequest();
        assertThatThrownBy(() -> parService.processPushedAuthRequest(request))
            .isInstanceOf(InvalidRequestException.class);

        // then
        verify(parDataPortOut, never()).init();
    }

    @Test
    void processRequestWithHandlerException() {
        // given - override handlers
        doThrow(new PidServerException("error"))
            .when(parHandler)
            .processPushedAuthRequest(any(ParRequest.class), any(AuthSession.class));
        doReturn(new ClientAttestationValidator.AttestationValues(TestUtils.CLIENT_PUBLIC_KEY, TestUtils.CLIENT_ATTESTATION_STATUS_LIST_REF))
            .when(clientAttestationValidator).validateClientAttestation(any(), any(), anyString());

        // given - mock session
        var mockSession = Mockito.mock(AuthSession.class);
        doReturn(mockSession).when(parDataPortOut).init();
        doReturn(Requests.PUSHED_AUTHORIZATION_REQUEST).when(mockSession).getNextExpectedRequest();

        // when
        var request = RequestUtil.getParRequest();
        assertThatThrownBy(() -> parService.processPushedAuthRequest(request))
            .isInstanceOf(PidServerException.class);

        // then
        verify(parDataPortOut).init();
        verify(parDataPortOut).save(mockSession);
    }

    @ValueSource(strings = {"state"})
    @ParameterizedTest
    void processRequestWithMissingOptionalParams(String optionalParam) {
        // given - override validator
        doReturn(new ClientAttestationValidator.AttestationValues(TestUtils.CLIENT_PUBLIC_KEY, TestUtils.CLIENT_ATTESTATION_STATUS_LIST_REF))
            .when(clientAttestationValidator).validateClientAttestation(any(), any(), anyString());

        // given - mock session
        var mockSession = Mockito.mock(AuthSession.class);
        doReturn(mockSession).when(parDataPortOut).init();
        doReturn(Requests.PUSHED_AUTHORIZATION_REQUEST).when(mockSession).getNextExpectedRequest();

        // when
        var requiredParams = RequestUtil.getValidParRequestParams();
        requiredParams.remove(optionalParam);
        var request = RequestUtil.getParRequest(requiredParams);
        parService.processPushedAuthRequest(request);

        // then
        verify(parDataPortOut).init();
        verify(parDataPortOut).save(mockSession);
        verify(parHandler).processPushedAuthRequest(request, mockSession);
    }
}
