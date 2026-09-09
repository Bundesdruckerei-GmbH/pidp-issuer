/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.exception;

import com.nimbusds.oauth2.sdk.token.DPoPTokenError;
import lombok.Getter;

@Getter
public class RequestUriExpiredException extends OAuthException {
    private final DPoPTokenError error;

    public RequestUriExpiredException(DPoPTokenError error) {
        super(error.getCode(), error.getDescription());
        this.error = error;
    }
}
