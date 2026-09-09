/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.policy;

import java.util.Set;

public record InvalidIssuanceDecision(Set<String> reasons) implements IssuanceDecision {

}
