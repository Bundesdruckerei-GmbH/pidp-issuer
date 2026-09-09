/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.exception;

import de.bdr.pidp.issuer.authorization.port.out.IdentificationFailedException;
import lombok.Getter;
import org.jspecify.annotations.Nullable;

@Getter
public class FinishAuthException extends RuntimeException {

    private final String error;
    @Nullable
    private final String redirectUri;
    @Nullable
    private final String state;
    @Nullable
    private final String errorDescription;

    public FinishAuthException(@Nullable String redirectUri, @Nullable String state, RuntimeException cause) {
        super(cause);
        this.redirectUri = redirectUri;
        this.state = state;
        if (cause instanceof IdentificationFailedException) {
            error = "access_denied";
            errorDescription = "Identification failed";
        } else if (cause instanceof OAuthException oe) {
            error = oe.getErrorCode();
            errorDescription = oe.getErrorDescription();
        } else {
            error = "server_error";
            errorDescription = null;
        }
    }
}
