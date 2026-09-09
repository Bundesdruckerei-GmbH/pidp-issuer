/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.exception;

public class InvalidProofException extends OIDException {

    public static final String ERROR_CODE = "invalid_proof";

    public InvalidProofException(String message) {
        super(ERROR_CODE, message);
    }

    public InvalidProofException(String message, Throwable cause) {
        super(ERROR_CODE, message, cause);
    }

    public InvalidProofException(String errorDescription, String message, Throwable cause) {
        super(ERROR_CODE, errorDescription, message, cause);
    }
}
