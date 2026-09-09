/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import de.bdr.pidp.issuer.authorization.core.domain.AccessTokenData;
import de.bdr.pidp.issuer.authorization.core.domain.SeedCredential;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSession;
import de.bdr.pidp.issuer.authorization.core.service.AccessTokenIssuer;
import de.bdr.pidp.issuer.testdata.ClientIds;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.assertj.core.data.Offset;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static de.bdr.pidp.issuer.authorization.ConfigTestData.AUTH_CONFIG;
import static de.bdr.pidp.issuer.testdata.TestUtils.DPOP_SCHEME;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

class TokenHandlerTest {

    private final AccessTokenIssuer accessTokenIssuer = mock(AccessTokenIssuer.class);

    private final TokenHandler tokenHandler = new TokenHandler(AUTH_CONFIG, accessTokenIssuer);

    @Test
    void shouldProcessAccessTokenRequest() throws ParseException {
        var issuerState = TestUtils.generateIssuerState();
        AuthSession session = new AuthSession(TestUtils.randomSessionId());
        session.addGeneratedAuthorizeProperties(issuerState);
        ReflectionTestUtils.setField(session, "authorizationCodeExpirationTime", Instant.now().plusSeconds(5));
        ReflectionTestUtils.setField(session, "clientId", ClientIds.validClientIdForSelfSigned().toString());
        ReflectionTestUtils.setField(session, "scope", "pid");

        var seedCredentialData = new SeedCredential("~~serialized~~", UUID.randomUUID().toString(), "subject", Instant.now().plusSeconds(600));

        doReturn(buildDummyJWTAccessToken()).when(accessTokenIssuer).buildAccessToken(any(), anyString(), anyString(), any(), any(), any());

        AccessTokenData accessTokenData =
            tokenHandler.processTokenRequest(session, seedCredentialData, new JWKThumbprintConfirmation(TestUtils.DEVICE_JWK_THUMBPRINT), "jti");

        assertThat(session.getAccessTokenID()).isNotNull();
        assertThat(session.getAuthorizationCodeExpirationTime()).isNotNull();
        assertThat(session.getSeedCredentialData()).isEqualTo(seedCredentialData.value());

        assertThat(accessTokenData).isNotNull();
        assertThat(accessTokenData.tokenType()).isEqualTo(DPOP_SCHEME);
        assertThat(accessTokenData.accessToken()).isNotNull();
        assertThat(accessTokenData.expiresIn()).isCloseTo(Duration.ofSeconds(60L).toSeconds(), Offset.offset(3L));
    }

    @Test
    void shouldProcessRefreshTokenRequest() throws ParseException {
        AuthSession session = new AuthSession(TestUtils.randomSessionId());
        ReflectionTestUtils.setField(session, "scope", "pid");

        doReturn(buildDummyJWTAccessToken()).when(accessTokenIssuer).buildAccessToken(any(), anyString(), anyString(), any(), any(), any());

        AccessTokenData accessTokenData = tokenHandler.processRefreshTokenRequest(session, new SeedCredential("value",
                UUID.randomUUID().toString(), "dummy", Instant.now()),
            ClientIds.validClientIdForSelfSigned().toString(), new JWKThumbprintConfirmation(TestUtils.DEVICE_JWK_THUMBPRINT), "jti");

        assertThat(session.getAccessTokenID()).isNotNull();

        assertThat(accessTokenData).isNotNull();
        assertThat(accessTokenData.tokenType()).isEqualTo(DPOP_SCHEME);
        assertThat(accessTokenData.accessToken()).isNotNull();
        assertThat(accessTokenData.expiresIn()).isCloseTo(Duration.ofSeconds(60L).toSeconds(), Offset.offset(3L));
    }

    private static SignedJWT buildDummyJWTAccessToken() throws ParseException {
        return new SignedJWT(
            new JWSHeader(JWSAlgorithm.ES256).toBase64URL(),
            new JWTClaimsSet.Builder().expirationTime(Date.from(Instant.now().plusSeconds(60))).build().toPayload().toBase64URL(),
            Base64URL.from("SIGNATUR")
        );
    }
}
