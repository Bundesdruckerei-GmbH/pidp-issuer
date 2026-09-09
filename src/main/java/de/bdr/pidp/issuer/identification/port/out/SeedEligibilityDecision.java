/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.port.out;

public sealed interface SeedEligibilityDecision permits EligibleSeedDecision, IneligibleSeedDecision {
}

