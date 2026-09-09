/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.port.out;

public class KeyNotFoundException extends RuntimeException {
    public KeyNotFoundException(String message) {
        super(message);
    }
}
