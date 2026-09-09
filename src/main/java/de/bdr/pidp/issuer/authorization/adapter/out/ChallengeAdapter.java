/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.adapter.out;

import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.authorization.port.out.ChallengeHousekeepingPortOut;
import de.bdr.pidp.issuer.authorization.port.out.ChallengePortOut;
import de.bdr.pidp.issuer.base.Nonce;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

@Service
@Slf4j
public class ChallengeAdapter implements ChallengePortOut, ChallengeHousekeepingPortOut {
    private final ChallengeRepository challengeRepository;
    private final Duration tolerance;

    public ChallengeAdapter(ChallengeRepository challengeRepository, AuthorizationConfiguration config) {
        this.challengeRepository = challengeRepository;
        this.tolerance = config.getProofTimeTolerance();
    }

    @Transactional
    @Override
    public void createAndSave(Nonce nonce) {
        ChallengeEntity entity = new ChallengeEntity();
        entity.setChallenge(nonce.nonce());
        // Postgres timestamp contains only microseconds and no nanoseconds
        entity.setExpires(nonce.expirationTime().truncatedTo(ChronoUnit.MICROS));
        challengeRepository.save(entity);
    }

    @Transactional
    @Override
    public Optional<Nonce> findAndDeleteByChallenge(String value) {
        return challengeRepository.findFirstByChallenge(value)
                .map(e -> {
                    challengeRepository.delete(e);
                    return e;
                })
                .map(this::map);
    }

    @Transactional
    public int deleteExpiredChallenges() {
        var expiryTime = Instant.now().minus(tolerance);
        return challengeRepository.deleteAllByExpiresBefore(expiryTime);
    }

    private Nonce map(final ChallengeEntity entity) {
        return new Nonce(entity.getChallenge(), entity.getExpires());
    }
}
