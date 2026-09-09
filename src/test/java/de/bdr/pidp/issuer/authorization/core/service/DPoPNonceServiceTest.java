/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.service;

import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSession;
import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.base.NonceFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.time.Instant;

import static de.bdr.pidp.issuer.authorization.ConfigTestData.AUTH_CONFIG;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DPoPNonceServiceTest {

    @Mock
    private AuthSession session;
    @Spy
    private AuthorizationConfiguration authConfig = AUTH_CONFIG;
    @InjectMocks
    private DPoPNonceService subject;

    private final Duration dpopLifetime = AUTH_CONFIG.getPopNonceLifetime();

    @Test
    void when_provideAndSave_then_ok() {
        var nonce = new Nonce("nonce_for_service", dpopLifetime);
        try (MockedStatic<NonceFactory> nonceFactoryMock = mockStatic(NonceFactory.class)) {
            nonceFactoryMock.when(() -> NonceFactory.createSecureRandomNonce(dpopLifetime))
                    .thenReturn(nonce);

            var result = subject.provideAndSave(session);

            assertThat(result).isEqualTo(nonce);
            verify(session).setDPoPNonce(nonce);
        }
    }

    @Test
    void when_fetch_then_ok() {
        var value = "diesIstDerNonceWert";
        when(session.getDpopNonce()).thenReturn(value);
        var exp = Instant.now().plusSeconds(17);
        when(session.getDpopNonceExpirationTime()).thenReturn(exp);

        var result = subject.fetchFromAuthSession(session);

        assertThat(result.nonce()).isEqualTo(value);
        assertThat(result.expirationTime()).isEqualTo(exp);
    }
}
