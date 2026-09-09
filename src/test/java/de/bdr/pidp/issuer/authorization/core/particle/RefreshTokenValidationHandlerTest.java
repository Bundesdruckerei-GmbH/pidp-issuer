/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import de.bdr.pidp.issuer.authorization.core.domain.SeedCredential;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSession;
import de.bdr.pidp.issuer.authorization.core.exception.InvalidGrantException;
import de.bdr.pidp.issuer.authorization.core.particle.refreshtoken.RefreshTokenValidator;
import de.bdr.pidp.issuer.authorization.port.out.IdentificationDataPortOut;
import de.bdr.pidp.issuer.authorization.port.out.InvalidSeedCredentialException;
import de.bdr.pidp.issuer.authorization.port.out.RefreshTokenLifecyclePortOut;
import de.bdr.pidp.issuer.testdata.ClientIds;
import de.bdr.pidp.issuer.testdata.TestRefreshTokenIssuer;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Isolated;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.text.ParseException;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

@ExtendWith(OutputCaptureExtension.class)
@Isolated
class RefreshTokenValidationHandlerTest {
    private final IdentificationDataPortOut identificationPort = mock(IdentificationDataPortOut.class);
    private final RefreshTokenValidator refreshTokenValidator = mock(RefreshTokenValidator.class);
    private final RefreshTokenLifecyclePortOut refreshTokenLifecyclePort = mock(RefreshTokenLifecyclePortOut.class);

    private final RefreshTokenValidationHandler handler = new RefreshTokenValidationHandler(identificationPort, refreshTokenValidator, refreshTokenLifecyclePort);

    private final SignedJWT refreshToken = TestRefreshTokenIssuer.buildRefreshToken();

    @Test
    void shouldProcessRefreshTokenRequest() throws ParseException {
        var refreshTokenRequest = RequestUtil.getRefreshTokenRequest();
        doReturn(new SeedCredential("seed", "reference", "sub", Instant.now())).when(identificationPort).verifySeedCredential(anyString());
        doReturn(refreshToken.getJWTClaimsSet()).when(refreshTokenValidator).validate(any(), anyString(), any(), any());
        doReturn(true).when(refreshTokenLifecyclePort).isTokenValid(refreshToken.getJWTClaimsSet().getJWTID());

        AuthSession session = new AuthSession(TestUtils.randomSessionId());

        assertThatCode(() -> handler.processRefreshTokenRequest(refreshTokenRequest, session, ClientIds.validClientIdForSelfSigned().toString(),
            new JWKThumbprintConfirmation(TestUtils.DEVICE_JWK_THUMBPRINT)))
            .doesNotThrowAnyException();
    }

    @Test
    void shouldThrowExceptionWhenSeedCredentialInvalid() throws ParseException {
        var refreshTokenRequest = RequestUtil.getRefreshTokenRequest();
        doThrow(new InvalidSeedCredentialException("Invalid Seed credential", new Exception())).when(identificationPort).verifySeedCredential(anyString());
        doReturn(refreshToken.getJWTClaimsSet()).when(refreshTokenValidator).validate(any(), anyString(), any(), any());
        doReturn(true).when(refreshTokenLifecyclePort).isTokenValid(refreshToken.getJWTClaimsSet().getJWTID());
        var clientId = ClientIds.validClientIdForSelfSigned().toString();
        var dpopJwkThumbprint = new JWKThumbprintConfirmation(TestUtils.DEVICE_JWK_THUMBPRINT);

        AuthSession session = new AuthSession(TestUtils.randomSessionId());

        assertThatThrownBy(() -> handler.processRefreshTokenRequest(refreshTokenRequest, session, clientId, dpopJwkThumbprint))
            .isInstanceOf(InvalidGrantException.class)
            .hasMessage("Seed credential at the refresh token is invalid");
    }

    @Test
    void shouldThrowExceptionWhenSeedCredentialLifecycleIsNotValid(CapturedOutput output) throws ParseException {
        var refreshTokenRequest = RequestUtil.getRefreshTokenRequest();
        var clientId = ClientIds.validClientIdForSelfSigned().toString();
        var dpopJwkThumbprint = new JWKThumbprintConfirmation(TestUtils.DEVICE_JWK_THUMBPRINT);
        var session = new AuthSession(TestUtils.randomSessionId());
        doReturn(new SeedCredential("seed", "reference", "sub", Instant.now())).when(identificationPort).verifySeedCredential(anyString());
        doReturn(refreshToken.getJWTClaimsSet()).when(refreshTokenValidator).validate(any(), anyString(), any(), any());
        doReturn(false).when(refreshTokenLifecyclePort).isTokenValid(refreshToken.getJWTClaimsSet().getJWTID());


        assertThatThrownBy(() -> handler.processRefreshTokenRequest(refreshTokenRequest, session, clientId, dpopJwkThumbprint))
            .isInstanceOf(InvalidGrantException.class)
            .hasMessage("Refresh token lifecycle status is invalid");
        assertThat(output).contains("logType=security", "Refresh token lifecycle status is not valid");
    }
}
