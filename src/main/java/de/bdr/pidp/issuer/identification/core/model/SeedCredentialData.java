/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core.model;

import de.bdr.pidp.issuer.base.identitydata.IdentityData;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.time.Instant;

@NullMarked
public record SeedCredentialData(String seedCredential, @Nullable IdentityData identityData, String jti, String sub, Instant exp) {
}
