/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base;

import java.time.Duration;
import java.time.Instant;

public record Nonce(String nonce, Instant expirationTime) {
    public Nonce(String nonce, Duration expiresIn) {
        this(nonce, Instant.now().plus(expiresIn));
    }
}
