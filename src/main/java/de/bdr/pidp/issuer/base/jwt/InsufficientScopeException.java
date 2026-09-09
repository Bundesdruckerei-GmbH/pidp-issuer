/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwt;

import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.Scope;
import lombok.Getter;

@Getter
public class InsufficientScopeException extends BadJWTException {

    private final Scope expected;

    public InsufficientScopeException(Scope expected) {
        super("JWT scope is insufficient");
        this.expected = expected;
    }
}
