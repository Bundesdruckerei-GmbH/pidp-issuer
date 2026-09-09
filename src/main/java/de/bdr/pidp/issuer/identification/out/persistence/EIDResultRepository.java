/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.out.persistence;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.NativeQuery;

import java.time.Instant;

public interface EIDResultRepository extends JpaRepository<EIDResultEntity, String> {

    @Modifying
    @NativeQuery(value = "DELETE FROM eid_result e WHERE e.expires < :refTime")
    int deleteAllByExpiresBefore(Instant refTime);
}
