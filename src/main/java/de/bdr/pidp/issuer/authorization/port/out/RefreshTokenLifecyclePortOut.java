/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.port.out;

import de.bdr.pidp.issuer.base.jwt.StatusListRef;
import org.jspecify.annotations.Nullable;

import java.time.Instant;

public interface RefreshTokenLifecyclePortOut {

    void registerToken(String jti, String pseudonym, Instant expiration, @Nullable StatusListRef statusListRef);

    boolean isTokenValid(String jti);
}
