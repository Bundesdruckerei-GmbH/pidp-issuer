/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core.exception;

public class AuthenticationNotFoundException extends RuntimeException {
    public AuthenticationNotFoundException(String message) {
        super(message);
    }
}
