/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core.exception;

public class InvalidEidData extends RuntimeException {
    public InvalidEidData() {
        super("The identification data is invalid or incomplete.");
    }
}
