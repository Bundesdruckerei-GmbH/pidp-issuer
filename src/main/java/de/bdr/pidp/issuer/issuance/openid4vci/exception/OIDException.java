/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.exception;

import lombok.Getter;

import java.util.HashMap;
import java.util.Map;

/**
 * Base class for exceptions during the OpenID protocol flow
 */
@Getter
public abstract class OIDException extends RuntimeException {

    private final String errorCode;
    private final String errorDescription;
    private final Map<String, String> header = new HashMap<>();

    protected OIDException(String errorCode) {
        super();
        this.errorCode = errorCode;
        errorDescription = null;
    }

    protected OIDException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
        errorDescription = message;
    }

    protected OIDException(String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
        errorDescription = message;
    }

    protected OIDException(String errorCode, String errorDescription, String message) {
        super(message);
        this.errorCode = errorCode;
        this.errorDescription = errorDescription;
    }

    protected OIDException(String errorCode, String errorDescription, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
        this.errorDescription = errorDescription;
    }

    public void addHeader(String key, String value) {
        header.put(key, value);
    }
}
