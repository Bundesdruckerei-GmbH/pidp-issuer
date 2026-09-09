/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.port.in;

public class SeedCredentialVerificationException extends RuntimeException {
    public SeedCredentialVerificationException(String message) {
        super(message);
    }
    public SeedCredentialVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
