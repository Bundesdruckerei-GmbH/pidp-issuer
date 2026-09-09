/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core.seedcredential;

public class SeedException extends RuntimeException {
    public SeedException(String message) {
        super(message);
    }
    public SeedException(String message, Throwable cause) {
        super(message, cause);
    }
}
