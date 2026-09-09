/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.exception;

public class InvalidClientException extends OAuthException {
    public InvalidClientException(String message) {
        super("invalid_client", message);
    }

    public InvalidClientException(String message, Throwable cause) {
        super("invalid_client", message, cause);
    }
}
