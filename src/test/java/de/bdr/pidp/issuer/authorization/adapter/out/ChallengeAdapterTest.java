/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.adapter.out;

import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.base.RandomUtil;
import de.bdr.pidp.issuer.end2end.integration.IntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@Transactional
class ChallengeAdapterTest extends IntegrationTest {
    public static final Duration CHALLENGE_EXPIRES_IN = Duration.ofSeconds(30);

    @Autowired
    private ChallengeAdapter adapter;

    @Autowired
    private ChallengeRepository repository;

    @Test
    void createAndSave() {
        var challengeValue = RandomUtil.randomString();
        var challenge = new Nonce(challengeValue, CHALLENGE_EXPIRES_IN);

        adapter.createAndSave(challenge);

        var entities = repository.findFirstByChallenge(challengeValue);
        assertThat(entities)
                .get()
                .extracting(ChallengeEntity::getChallenge)
                .isEqualTo(challengeValue);
    }

    @Test
    void findAndDelete() {
        var challengeValue = RandomUtil.randomString();
        var challenge = new Nonce(challengeValue, CHALLENGE_EXPIRES_IN);

        adapter.createAndSave(challenge);

        var deleted = adapter.findAndDeleteByChallenge(challengeValue);

        assertThat(deleted)
                .isNotEmpty()
                .get()
                .extracting(Nonce::nonce)
                .isEqualTo(challengeValue);
        Optional<ChallengeEntity> optionalChallengeEntity = repository.findFirstByChallenge(challengeValue);
        assertThat(optionalChallengeEntity).isEmpty();
    }

    @Test
    void cleanupExpiredChallenges() {
        var active = repository.save(createEntity(Instant.now().plusSeconds(120)));
        var withinTolerance = repository.save(createEntity(Instant.now().minusSeconds(3)));
        var expired = repository.save(createEntity(Instant.now().minusSeconds(120)));

        var deleted = adapter.deleteExpiredChallenges();

        // the own 'expired' one and may be other entries from other tests
        assertThat(deleted).isGreaterThanOrEqualTo(1);
        assertThat(repository.existsById(active.getId())).isTrue();
        assertThat(repository.existsById(withinTolerance.getId())).isTrue();
        assertThat(repository.existsById(expired.getId())).isFalse();
    }

    private static ChallengeEntity createEntity(Instant expires) {
        var challenge = new ChallengeEntity();
        challenge.setChallenge(RandomUtil.randomString());
        challenge.setExpires(expires);
        return challenge;
    }
}
