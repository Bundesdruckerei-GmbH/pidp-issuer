/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base;

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

@NullMarked
public record VerificationResult(VerificationStatus status, @Nullable String error) {

    public static VerificationResult success() {
        return new VerificationResult(VerificationStatus.SUCCESS, null);
    }

    public static VerificationResult error(String message) {
        return new VerificationResult(VerificationStatus.ERROR, message);
    }

    public enum VerificationStatus {
        SUCCESS, ERROR;

        public boolean isError() {
            return this == ERROR;
        }
    }
}
