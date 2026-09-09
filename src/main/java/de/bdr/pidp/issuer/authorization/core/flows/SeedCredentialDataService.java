/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.flows;

import de.bdr.pidp.issuer.authorization.in.SeedCredentialDataPortIn;
import de.bdr.pidp.issuer.authorization.port.out.SeedCredentialDataPortOut;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
class SeedCredentialDataService implements SeedCredentialDataPortIn {

    private final SeedCredentialDataPortOut seedCredentialDataPortOut;

    @Override
    public String retrieveSeedCredentialData(String seedCredentialRef) {
        return seedCredentialDataPortOut.loadBySeedCredentialRef(seedCredentialRef).getSeedCredentialData();
    }
}
