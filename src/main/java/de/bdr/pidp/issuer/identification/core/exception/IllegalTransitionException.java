/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core.exception;

public class IllegalTransitionException extends RuntimeException {
    public IllegalTransitionException(String message) {
        super(message);
    }
}
