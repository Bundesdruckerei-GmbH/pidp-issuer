/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import de.bdr.pidp.issuer.authorization.core.domain.FinishAuthRequest;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSession;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidGrantException;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidRequestException;
import de.bdr.pidp.issuer.authorization.port.out.IdentificationDataPortOut;
import de.bdr.pidp.issuer.authorization.port.out.IdentificationFailedException;
import de.bdr.pidp.issuer.base.RandomUtil;
import de.bdr.pidp.issuer.base.VerificationResult;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;

import static de.bdr.pidp.issuer.authorization.ConfigTestData.AUTH_CONFIG;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FinishAuthorizationHandlerTest {
    private final FinishAuthRequest validRequest = RequestUtil.getFinishAuthRequest();
    private final IdentificationDataPortOut identificationProvider = mock(IdentificationDataPortOut.class);

    private final FinishAuthorizationHandler handler = new FinishAuthorizationHandler(AUTH_CONFIG, identificationProvider);

    @Test
    void shouldProcess() throws URISyntaxException {
        String issuerState = validRequest.getIssuerState();

        when(identificationProvider.checkIdentification(anyString())).thenReturn(VerificationResult.success());

        AuthSession authSession = new AuthSession(TestUtils.randomSessionId());
        authSession.addGeneratedAuthorizeProperties(issuerState);
        ReflectionTestUtils.setField(authSession, "redirectUri", "https://redirect.localhost");
        ReflectionTestUtils.setField(authSession, "state", "any Statevalue from Client");

        String redirectUriString = handler.processFinishAuthRequest(validRequest, authSession);

        assertThat(redirectUriString).isNotNull();
        URI redirectUri = new URI(redirectUriString);
        assertThat(redirectUri.getScheme()).isEqualTo("https");
        assertThat(redirectUri.getHost()).isEqualTo("redirect.localhost");
        assertThat(redirectUri.getQuery()).contains("code=", "iss=" + AUTH_CONFIG.getCredentialIssuerIdentifier());
        assertThat(redirectUri.getRawQuery()).contains("state=any%20Statevalue%20from%20Client");

        assertThat(authSession.getAuthorizationCodeExpirationTime()).isNotNull().isAfter(Instant.now());
    }

    @Test
    void shouldThrowExceptionWhenIssuerStatesAreDifferent() {
        AuthSession authSession = new AuthSession(TestUtils.randomSessionId());
        authSession.addGeneratedAuthorizeProperties(RandomUtil.randomString());

        assertThatThrownBy(() -> handler.processFinishAuthRequest(validRequest, authSession))
            .isInstanceOf(InvalidGrantException.class)
            .hasMessage("Invalid issuer state");
    }

    @Test
    void shouldThrowExceptionWhenRedirectUriIsMissing() {
        var session = givenSessionWithIssuerState(validRequest.getIssuerState());

        assertThatThrownBy(() -> handler.processFinishAuthRequest(validRequest, session))
            .isInstanceOf(InvalidRequestException.class)
            .hasMessage("Missing redirect uri");
    }

    @Test
    void given_noIdentificationResult_when_process_then_throwException() {
        var session = givenSessionWithIssuerState(validRequest.getIssuerState());
        ReflectionTestUtils.setField(session, "redirectUri", "https://redirect.localhost");
        doThrow(IdentificationFailedException.class).when(identificationProvider).checkIdentification(anyString());

        assertThatThrownBy(() -> handler.processFinishAuthRequest(validRequest, session))
            .isInstanceOf(IdentificationFailedException.class);
    }

    @Test
    void given_identificationResultError_when_process_then_throwException() {
        var session = givenSessionWithIssuerState(validRequest.getIssuerState());
        ReflectionTestUtils.setField(session, "redirectUri", "https://redirect.localhost");
        var details = "USER_ABORTED";
        doReturn(VerificationResult.error(details)).when(identificationProvider).checkIdentification(anyString());

        assertThatThrownBy(() -> handler.processFinishAuthRequest(validRequest, session))
            .hasMessage(details)
            .isInstanceOf(IdentificationFailedException.class);
    }

    private AuthSession givenSessionWithIssuerState(String issuerState) {
        AuthSession authSession = new AuthSession(TestUtils.randomSessionId());
        authSession.addGeneratedAuthorizeProperties(issuerState);
        return authSession;
    }
}
