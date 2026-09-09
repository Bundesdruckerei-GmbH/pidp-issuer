/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.exception;

import lombok.Getter;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

@Getter
@NullMarked
public class InvalidAccessTokenException extends RuntimeException {

    private final Reason reason;
    @Nullable
    private final String errorDescription;

    public InvalidAccessTokenException(Reason reason) {
        this.reason = reason;
        this.errorDescription = null;
    }

    public InvalidAccessTokenException(Reason reason, String description) {
        this.reason = reason;
        this.errorDescription = description;
    }

    public enum Reason {
        MISSING_TOKEN,
        INVALID_TOKEN,
        INSUFFICIENT_SCOPE
    }
}
