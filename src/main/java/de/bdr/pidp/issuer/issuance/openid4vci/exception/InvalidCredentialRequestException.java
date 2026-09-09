/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.exception;

public class InvalidCredentialRequestException extends OIDException {

    private static final String ERROR_CODE = "invalid_credential_request";

    public InvalidCredentialRequestException(String message, Throwable cause) {
        super(ERROR_CODE, message, cause);
    }

    public InvalidCredentialRequestException(String errorDescription, String message, Throwable cause) {
        super(ERROR_CODE, errorDescription, message, cause);
    }

    public InvalidCredentialRequestException(String message) {
        super(ERROR_CODE, message);
    }

}
