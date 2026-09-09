/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.adapter.out;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.NativeQuery;

import java.time.Instant;
import java.util.Optional;

public interface ChallengeRepository extends JpaRepository<ChallengeEntity, Long> {
    Optional<ChallengeEntity> findFirstByChallenge(String challenge);

    @Modifying
    @NativeQuery(value = "DELETE FROM challenge c WHERE c.expires < :time")
    int deleteAllByExpiresBefore(Instant time);
}
