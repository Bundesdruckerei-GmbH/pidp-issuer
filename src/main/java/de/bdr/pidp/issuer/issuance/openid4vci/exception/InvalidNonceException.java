/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.exception;

public class InvalidNonceException extends OIDException {
    public InvalidNonceException(String errorDescription, String message, Throwable cause) {
        super("invalid_nonce", errorDescription, message, cause);
    }

    public InvalidNonceException(String message) {
        super("invalid_nonce", message);
    }
}
