/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.config.model;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public enum AttackPotentialResistance {
    ISO_18045_HIGH("iso_18045_high"),
    ISO_18045_MODERATE("iso_18045_moderate"),
    ISO_18045_ENHANCED_BASIC("iso_18045_enhanced-basic"),
    ISO_18045_BASIC("iso_18045_basic");

    private final String name;
}
