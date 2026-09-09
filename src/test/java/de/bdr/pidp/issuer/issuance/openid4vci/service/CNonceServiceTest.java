/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service;

import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.base.RandomUtil;
import de.bdr.pidp.issuer.issuance.config.IssuanceConfiguration;
import de.bdr.pidp.issuer.issuance.openid4vci.out.persistence.CNonceAdapter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static de.bdr.pidp.issuer.issuance.ConfigTestData.ISSUANCE_CONFIG;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class CNonceServiceTest {

    @Mock
    private CNonceAdapter cNonceAdapter;

    @Spy
    private IssuanceConfiguration issuanceConfiguration = ISSUANCE_CONFIG;

    @InjectMocks
    private CNonceService subject;

    @Test
    void testProvide() {
        var nonce = subject.provide();

        assertThat(nonce).isNotNull();
        verify(cNonceAdapter).createAndSave(nonce);
    }

    @Test
    void consumeFreshProvidedNonce() {
        var nonce = subject.provide();
        doReturn(Optional.of(nonce)).when(cNonceAdapter).findAndDeleteByNonce(argThat(n -> n.nonce().equals(nonce.nonce())));

        var consumed = subject.consume(nonce.nonce());

        assertThat(consumed).isTrue();
    }

    @Test
    void consumeNonceWithExpirationWithinTolerance() {
        var nonce = new Nonce(
                RandomUtil.randomString(),
                Instant.now().minusSeconds(5)
        );
        doReturn(Optional.of(nonce)).when(cNonceAdapter).findAndDeleteByNonce(argThat(n -> n.nonce().equals(nonce.nonce())));

        var consumed = subject.consume(nonce.nonce());

        assertThat(consumed).isTrue();
    }

    @Test
    void consumeExpiredNonce() {
        var nonce = new Nonce(
                RandomUtil.randomString(),
                Instant.now().minus(issuanceConfiguration.getProofTimeTolerance()).minusSeconds(5)
        );
        doReturn(Optional.of(nonce)).when(cNonceAdapter).findAndDeleteByNonce(argThat(n -> n.nonce().equals(nonce.nonce())));

        var consumed = subject.consume(nonce.nonce());

        assertThat(consumed).isFalse();
    }
}
