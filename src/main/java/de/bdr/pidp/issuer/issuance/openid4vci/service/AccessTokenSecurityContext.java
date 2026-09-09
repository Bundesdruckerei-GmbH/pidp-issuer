/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Issuer;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NullMarked;

@NullMarked
@RequiredArgsConstructor
@Getter
public class AccessTokenSecurityContext implements SecurityContext {

    private final Issuer authServer;
    private final Scope scope;
}
