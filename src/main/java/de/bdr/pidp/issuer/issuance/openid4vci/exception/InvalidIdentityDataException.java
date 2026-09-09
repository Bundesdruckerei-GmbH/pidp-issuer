/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.exception;

public class InvalidIdentityDataException extends OIDException {

    public static final String ERROR_CODE = "credential_request_denied";

    public InvalidIdentityDataException(String message) {
        super(ERROR_CODE, message);
    }
}
