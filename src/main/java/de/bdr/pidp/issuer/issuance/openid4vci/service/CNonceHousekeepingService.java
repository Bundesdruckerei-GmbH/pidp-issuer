/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service;

import de.bdr.pidp.issuer.issuance.config.IssuanceConfiguration;
import de.bdr.pidp.issuer.issuance.openid4vci.out.persistence.CNonceAdapter;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class CNonceHousekeepingService {
    private final Duration proofTimeTolerance;
    private final CNonceAdapter cNonceAdapter;

    public CNonceHousekeepingService(IssuanceConfiguration configuration, CNonceAdapter cNonceAdapter) {
        this.proofTimeTolerance = configuration.getProofTimeTolerance();
        this.cNonceAdapter = cNonceAdapter;
    }

    public void cleanupExpiredNonces() {
        cNonceAdapter.cleanupExpiredNonces(proofTimeTolerance);
    }
}
