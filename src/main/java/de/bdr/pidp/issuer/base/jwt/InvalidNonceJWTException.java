/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwt;

import com.nimbusds.jwt.proc.BadJWTException;

public class InvalidNonceJWTException extends BadJWTException {
    public InvalidNonceJWTException(String message) {
        super(message);
    }
}
