/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.adapter.out;

import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.time.Instant;

record PIDMasterTokenRef(String tokenID, Instant expiration, String pseudonym, @Nullable PMTStatusListRef statusListRef) {
}

record PMTStatusListRef(URI uri, int index) {
}
