/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base;

public class PidpServiceUnavailableException extends RuntimeException {
    public PidpServiceUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
