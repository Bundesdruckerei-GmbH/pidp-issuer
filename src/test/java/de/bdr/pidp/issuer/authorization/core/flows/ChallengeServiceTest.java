/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.flows;

import de.bdr.pidp.issuer.authorization.core.service.AuthChallengeService;
import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.base.RandomUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;

@ExtendWith(MockitoExtension.class)
class ChallengeServiceTest {

    @Mock
    private AuthChallengeService authChallengeService;

    @InjectMocks
    private ChallengeService challengeService;

    @Test
    void processChallengeRequest() {
        // given
        var challenge = new Nonce(RandomUtil.randomString(), Duration.ofSeconds(30));
        doReturn(challenge).when(authChallengeService).provide();

        // when
        var result = challengeService.processChallengeRequest();

        // then
        assertThat(result.attestationChallenge()).isEqualTo(challenge.nonce());
    }
}
