/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.crypto.hsm;

public class HSMKeyException extends RuntimeException {
    HSMKeyException(Throwable throwable) {
        super(throwable);
    }

    HSMKeyException(String message) {
        super(message);
    }
}
