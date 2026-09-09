/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.exception;

public class InvalidEncryptionParametersException extends OIDException {
    public InvalidEncryptionParametersException(String message) {
        super("invalid_encryption_parameters", message);
    }

    public InvalidEncryptionParametersException(String message, Throwable cause) {
        super("invalid_encryption_parameters", message, cause);
    }
}
