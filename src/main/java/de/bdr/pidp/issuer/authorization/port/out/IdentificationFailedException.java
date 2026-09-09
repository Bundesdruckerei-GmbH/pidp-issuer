/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.port.out;

public class IdentificationFailedException extends RuntimeException {

    public IdentificationFailedException(String message) {
        super(message);
    }

    public IdentificationFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}
