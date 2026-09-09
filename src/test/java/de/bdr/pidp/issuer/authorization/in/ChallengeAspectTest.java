/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.in;

import de.bdr.pidp.issuer.authorization.config.MetaTestData;
import de.bdr.pidp.issuer.authorization.core.exception.DPoPValidationException;
import de.bdr.pidp.issuer.authorization.core.service.AuthChallengeService;
import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.base.PidServerException;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.HashSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class ChallengeAspectTest {
    private final AuthChallengeService authChallengeMock = mock(AuthChallengeService.class);
    private final ChallengeAspect aspect = new ChallengeAspect(authChallengeMock);

    @Test
    void shouldAddChallengeHeaderOnOAuthException() {
        // given
        var ex = DPoPValidationException.useDPoPNonce(new HashSet<>(MetaTestData.AUTH_METADATA.getDPoPJWSAlgs()), "hier gibt's nonce zu sehen");
        var challenge = new Nonce("challenging", Duration.ofSeconds(30));
        doReturn(challenge).when(authChallengeMock).provide();

        // when
        aspect.refreshTokenException(ex);

        // then
        assertThat(ex.getHeader()).containsEntry("OAuth-Client-Attestation-Challenge", "challenging");
    }

    @Test
    void shouldNotAddChallengeOnRegularException() {
        // given
        var ex = new PidServerException("So endet’s");

        // when
        aspect.refreshTokenException(ex);

        // then
        verify(authChallengeMock, never()).provide();
    }
}
