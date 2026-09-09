/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.out.kms;

public class KMSKeyException extends RuntimeException {
    public KMSKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
