/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.out.persistence;

import org.jspecify.annotations.NullMarked;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.NativeQuery;

import java.time.Instant;
import java.util.Optional;

@NullMarked
public interface AuthSessionRepository extends JpaRepository<AuthSessionEntity, Long> {
    Optional<AuthSessionEntity> findFirstByRequestUri(String requestUri);
    Optional<AuthSessionEntity> findFirstByAuthorizationCode(String authorizationCode);
    Optional<AuthSessionEntity> findFirstByIssuerState(String issuerState);
    Optional<AuthSessionEntity> findFirstByAccessTokenID(String accessTokenID);
    Optional<AuthSessionEntity> findFirstBySeedCredentialRef(String seedCredentialRef);
    Optional<AuthSessionEntity> findFirstByRefreshTokenID(String refreshTokenID);

    @Modifying
    @NativeQuery(value = "DELETE FROM auth_session p WHERE p.expires < :now")
    int deleteAllByExpiresBefore(Instant now);
}
