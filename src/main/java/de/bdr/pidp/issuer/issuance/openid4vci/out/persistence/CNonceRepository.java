/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.out.persistence;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.NativeQuery;

import java.time.Instant;
import java.util.Optional;

public interface CNonceRepository extends JpaRepository<CNonceEntity, Long> {
    Optional<CNonceEntity> findFirstByNonce(String nonce);

    @Modifying
    @NativeQuery(value = "DELETE FROM c_nonce c WHERE c.expires < :time")
    int deleteAllByExpiresBefore(Instant time);
}
