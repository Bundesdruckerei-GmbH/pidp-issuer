/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.service;

import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.authorization.port.out.ChallengePortOut;
import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.base.NonceFactory;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;

@Service
public class AuthChallengeService {

    private final ChallengePortOut challengePort;
    private final Duration lifetime;
    private final Duration tolerance;

    public AuthChallengeService(ChallengePortOut challengePort, AuthorizationConfiguration config) {
        this.challengePort = challengePort;
        lifetime = config.getPopNonceLifetime();
        tolerance = config.getProofTimeTolerance();
    }

    public Nonce provide() {
        var challenge = NonceFactory.createSecureRandomNonce(lifetime);
        challengePort.createAndSave(challenge);
        return challenge;
    }

    public boolean consume(String challenge) {
        var nowWithTolerance = Instant.now().minus(tolerance);
        return challengePort.findAndDeleteByChallenge(challenge)
            .filter(n -> n.expirationTime().isAfter(nowWithTolerance))
            .isPresent();
    }
}
