/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.exception;

public class InvalidScopeException extends OAuthException {

    public InvalidScopeException(String message) {
        super("invalid_scope", message);
    }

    public InvalidScopeException(Throwable cause) {
        super("invalid_scope", null, cause);
    }
}
