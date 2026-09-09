/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.in;

import de.bdr.pidp.issuer.authorization.core.AuthorizationHousekeeping;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.actuate.endpoint.annotation.WriteOperation;
import org.springframework.boot.actuate.endpoint.web.annotation.WebEndpoint;
import org.springframework.stereotype.Component;

@Component("authorizationHousekeepingController")
@WebEndpoint(id = "authHousekeeping")
@RequiredArgsConstructor
public class HousekeepingController {

    private final AuthorizationHousekeeping authorizationHousekeeping;

    @WriteOperation
    public void housekeeping() {
        authorizationHousekeeping.cleanupExpiredSessions();
        authorizationHousekeeping.cleanupExpiredChallenges();
    }
}
