/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.exception;

public class UnsupportedGrantTypeException extends OAuthException {
    public UnsupportedGrantTypeException(String message) {
        super("unsupported_grant_type", null, message);
    }
}
