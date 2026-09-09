/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.adapter.in;

import de.bdr.pidp.issuer.identification.core.IdentificationHousekeeping;
import org.springframework.boot.actuate.endpoint.annotation.WriteOperation;
import org.springframework.boot.actuate.endpoint.web.annotation.WebEndpoint;
import org.springframework.stereotype.Component;

@Component("identificationHousekeepingController")
@WebEndpoint(id = "identHousekeeping")
public class HousekeepingController {

    private final IdentificationHousekeeping identificationHousekeeping;

    public HousekeepingController(IdentificationHousekeeping identificationHousekeeping) {
        this.identificationHousekeeping = identificationHousekeeping;
    }

    @WriteOperation
    public void housekeeping() {
        identificationHousekeeping.cleanupExpiredAuthentications();
    }
}
