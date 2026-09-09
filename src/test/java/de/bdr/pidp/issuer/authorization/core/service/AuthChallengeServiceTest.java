/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.service;

import de.bdr.pidp.issuer.authorization.ConfigTestData;
import de.bdr.pidp.issuer.authorization.adapter.out.ChallengeAdapter;
import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.base.RandomUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class AuthChallengeServiceTest {

    @Mock
    private ChallengeAdapter challengeAdapter;

    @Spy
    private AuthorizationConfiguration authConfig = ConfigTestData.AUTH_CONFIG;

    @InjectMocks
    private AuthChallengeService subject;

    @Test
    void testProvide() {
        var challenge = subject.provide();

        assertThat(challenge).isNotNull();
        verify(challengeAdapter).createAndSave(challenge);
    }

    @Test
    void consumeFreshProvidedChallenge() {
        var challenge = subject.provide();
        doReturn(Optional.of(challenge)).when(challengeAdapter).findAndDeleteByChallenge(argThat(n -> n.equals(challenge.nonce())));

        var consumed = subject.consume(challenge.nonce());

        assertThat(consumed).isTrue();
    }

    @Test
    void consumeChallengeWithExpirationWithinTolerance() {
        var challenge = new Nonce(
                RandomUtil.randomString(),
                Instant.now().minusSeconds(5)
        );
        doReturn(Optional.of(challenge)).when(challengeAdapter).findAndDeleteByChallenge(argThat(n -> n.equals(challenge.nonce())));

        var consumed = subject.consume(challenge.nonce());

        assertThat(consumed).isTrue();
    }

    @Test
    void consumeExpiredChallenge() {
        var challenge = new Nonce(
                RandomUtil.randomString(),
                Instant.now().minus(authConfig.getProofTimeTolerance()).minusSeconds(5)
        );
        doReturn(Optional.of(challenge)).when(challengeAdapter).findAndDeleteByChallenge(argThat(n -> n.equals(challenge.nonce())));

        var consumed = subject.consume(challenge.nonce());

        assertThat(consumed).isFalse();
    }
}
