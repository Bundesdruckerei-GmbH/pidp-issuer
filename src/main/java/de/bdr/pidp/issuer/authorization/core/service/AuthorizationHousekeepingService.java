/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.service;

import de.bdr.pidp.issuer.authorization.core.AuthorizationHousekeeping;
import de.bdr.pidp.issuer.authorization.port.out.AuthorizationHousekeepingPortOut;
import de.bdr.pidp.issuer.authorization.port.out.ChallengeHousekeepingPortOut;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthorizationHousekeepingService implements AuthorizationHousekeeping {
    private final AuthorizationHousekeepingPortOut authorizationHousekeepingPortOut;
    private final ChallengeHousekeepingPortOut challengeHousekeepingPortOut;

    @Override
    public void cleanupExpiredSessions() {
        var count = authorizationHousekeepingPortOut.deleteExpiredSessions();
        log.info("Deleted {} expired sessions", count);
    }

    @Override
    public void cleanupExpiredChallenges() {
        var count = challengeHousekeepingPortOut.deleteExpiredChallenges();
        log.info("Deleted {} expired challenges", count);
    }
}
