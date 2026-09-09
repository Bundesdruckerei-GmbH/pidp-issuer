/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.port.out;

import de.bdr.pidp.issuer.base.identitydata.IdentityData;

public interface SeedEligibilityPolicyPort {
    default SeedEligibilityDecision evaluateSeedEligibilityPolicy(IdentityData identityData) {
        return new EligibleSeedDecision();
    }
}
