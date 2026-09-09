/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.doc.in;

import java.time.LocalDate;

public record CredentialConfigurationDoc(String credentialConfigurationId,
                                         CredentialConfigurationStatus status,
                                         LocalDate activationDate,
                                         LocalDate expirationDate) {
}
