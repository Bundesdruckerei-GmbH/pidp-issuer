/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.port.in;

public class ResourceDoesNotExistException extends RuntimeException {
    public ResourceDoesNotExistException(String message, Throwable cause) {
        super(message, cause);
    }
}
