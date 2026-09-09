/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.out.identification;

public class InvalidSeedCredentialException extends RuntimeException {
    public InvalidSeedCredentialException(String message, Throwable cause) {
        super(message,  cause);
    }
}
