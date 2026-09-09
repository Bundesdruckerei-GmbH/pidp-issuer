/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.policy;

import de.bdr.pidp.issuer.base.identitydata.IdentityData;
import de.bdr.pidp.issuer.identification.port.out.EligibleSeedDecision;
import de.bdr.pidp.issuer.identification.port.out.IneligibleSeedDecision;
import de.bdr.pidp.issuer.identification.port.out.SeedEligibilityDecision;
import de.bdr.pidp.issuer.identification.port.out.SeedEligibilityPolicyPort;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class SeedEligibilityPolicyAdapter implements SeedEligibilityPolicyPort {

    @Override
    public SeedEligibilityDecision evaluateSeedEligibilityPolicy(IdentityData identityData) {
        IssuanceDecision issuanceDecision = PidIdentityDataValidator.validatePidIdentityData(identityData);
        return switch (issuanceDecision) {
            case ValidIssuanceDecision _ -> new EligibleSeedDecision();
            case InvalidIssuanceDecision(Set<String> reasons) -> new IneligibleSeedDecision(reasons);
        };
    }
}
