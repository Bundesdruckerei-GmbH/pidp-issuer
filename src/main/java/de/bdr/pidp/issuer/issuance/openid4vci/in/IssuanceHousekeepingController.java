/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.in;

import de.bdr.pidp.issuer.issuance.openid4vci.service.CNonceHousekeepingService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.actuate.endpoint.annotation.WriteOperation;
import org.springframework.boot.actuate.endpoint.web.annotation.WebEndpoint;
import org.springframework.stereotype.Component;

@Component("issuanceHousekeepingController")
@WebEndpoint(id = "issuanceHousekeeping")
@RequiredArgsConstructor
public class IssuanceHousekeepingController {

    private final CNonceHousekeepingService cNonceHousekeepingService;

    @WriteOperation
    public void housekeeping() {
        cNonceHousekeepingService.cleanupExpiredNonces();
    }
}
