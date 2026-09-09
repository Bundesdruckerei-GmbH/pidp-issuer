/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import de.bdr.pidp.issuer.authorization.core.domain.RefreshTokenData;
import de.bdr.pidp.issuer.authorization.core.domain.SeedCredential;
import de.bdr.pidp.issuer.authorization.core.service.RefreshTokenIssuer;
import de.bdr.pidp.issuer.authorization.port.out.RefreshTokenLifecyclePortOut;
import de.bdr.pidp.issuer.testdata.ClientIds;
import de.bdr.pidp.issuer.testdata.TestRefreshTokenIssuer;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.assertj.core.data.Offset;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class RefreshTokenIssuanceHandlerTest {
    private final RefreshTokenIssuer refreshTokenIssuer = mock(RefreshTokenIssuer.class);
    private final RefreshTokenLifecyclePortOut refreshTokenLifecyclePort = mock(RefreshTokenLifecyclePortOut.class);

    private final RefreshTokenIssuanceHandler handler = new RefreshTokenIssuanceHandler(refreshTokenIssuer, refreshTokenLifecyclePort);

    @Test
    @DisplayName("Verify refresh token issuance on token request is successful")
    void test001() throws ParseException {
        var clientId = ClientIds.validClientIdForSelfSigned().toString();
        var dpopJwkThumbprint = new JWKThumbprintConfirmation(TestUtils.DEVICE_JWK_THUMBPRINT);
        var seedCredential = new SeedCredential("seedCredential", UUID.randomUUID().toString(), "subperlativ", Instant.now().plusSeconds(600));
        var statusRef = TestUtils.CLIENT_ATTESTATION_STATUS_LIST_REF;

        var refreshToken = TestRefreshTokenIssuer.buildRefreshToken();
        doReturn(refreshToken).when(refreshTokenIssuer).buildRefreshToken(anyString(), anyString(), any(), any());

        RefreshTokenData returnedRefreshTokenData = handler.processTokenRequest(clientId, "pid", dpopJwkThumbprint, seedCredential, statusRef);

        assertThat(returnedRefreshTokenData).isNotNull();
        assertThat(returnedRefreshTokenData.refreshToken().serialize()).isNotNull().matches("^[\\w-]+\\.[\\w-]+\\.[\\w-]+$");
        assertThat(returnedRefreshTokenData.expiresIn()).isCloseTo(Duration.ofDays(730).toSeconds(), Offset.offset(30L));
        var rtcs = refreshToken.getJWTClaimsSet();
        verify(refreshTokenLifecyclePort).registerToken(rtcs.getJWTID(), rtcs.getSubject(), rtcs.getExpirationTime().toInstant(), statusRef);
    }
}
