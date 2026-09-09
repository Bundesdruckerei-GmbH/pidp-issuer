/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests;

public class ProofParseException extends RuntimeException {

    public ProofParseException(String message, Throwable cause) {
        super(message, cause);
    }
}
