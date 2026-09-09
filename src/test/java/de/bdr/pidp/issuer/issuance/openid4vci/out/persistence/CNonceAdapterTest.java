/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.out.persistence;

import de.bdr.pidp.issuer.base.RandomUtil;
import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.end2end.integration.IntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class CNonceAdapterTest extends IntegrationTest {
    public static final Duration NONCE_EXPIRES_IN = Duration.ofSeconds(30);

    @Autowired
    private CNonceAdapter subject;

    @Autowired
    private CNonceRepository repository;

    @Test
    void createAndSafe() {
        var nonceValue = RandomUtil.randomString();
        var nonce = new Nonce(nonceValue, NONCE_EXPIRES_IN);

        subject.createAndSave(nonce);

        var entities = repository.findFirstByNonce(nonceValue);
        assertThat(entities)
                .get()
                .extracting(CNonceEntity::getNonce)
                .isEqualTo(nonceValue);
    }

    @Test
    void findAndDelete() {
        var nonceValue = RandomUtil.randomString();
        var nonce = new Nonce(nonceValue, NONCE_EXPIRES_IN);
        subject.createAndSave(nonce);

        var deleted = subject.findAndDeleteByNonce(nonce);

        assertThat(deleted)
                .isNotEmpty()
                .get()
                .extracting(Nonce::nonce)
                .isEqualTo(nonceValue);
        Optional<CNonceEntity> optionalCNonceEntity = repository.findFirstByNonce(nonceValue);
        assertThat(optionalCNonceEntity).isEmpty();
    }

    @Test
    void cleanupExpired() {
        var active = repository.save(createEntity(Instant.now().plusSeconds(120)));
        var withinTolerance = repository.save(createEntity(Instant.now().minusSeconds(15)));
        var expired = repository.save(createEntity(Instant.now().minusSeconds(120)));

        subject.cleanupExpiredNonces(Duration.ofSeconds(30));

        assertThat(repository.existsById(active.getId())).isTrue();
        assertThat(repository.existsById(withinTolerance.getId())).isTrue();
        assertThat(repository.existsById(expired.getId())).isFalse();
    }

    private static CNonceEntity createEntity(Instant expires) {
        var nonce = new CNonceEntity();
        nonce.setNonce(RandomUtil.randomString());
        nonce.setExpires(expires);
        return nonce;
    }
}
