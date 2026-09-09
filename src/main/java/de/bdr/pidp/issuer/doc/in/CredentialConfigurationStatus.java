/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.doc.in;

import lombok.Getter;

@Getter
public enum CredentialConfigurationStatus {
    ACTIVE("Active"),
    DEPRECATED("Deprecated"),
    REMOVED("Removed"),
    INACTIVE("Inactive");

    private final String displayString;

    CredentialConfigurationStatus(String displayString) {
        this.displayString = displayString;
    }
}
