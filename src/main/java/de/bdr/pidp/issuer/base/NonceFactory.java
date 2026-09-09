/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.time.Duration;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class NonceFactory {

    /**
     * Generates a nonce as a secure random string consisting of 44 characters of the set [a-zA-Z0-9]
     */
    public static Nonce createSecureRandomNonce(Duration expiresIn) {
        return new Nonce(RandomUtil.randomString(), expiresIn);
    }
}
