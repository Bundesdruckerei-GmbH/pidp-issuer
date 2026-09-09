/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle.refreshtoken;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.Scope;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NullMarked;

@NullMarked
@RequiredArgsConstructor
@Getter
public class RefreshTokenSecurityContext implements SecurityContext {

    private final String clientID;
    private final Base64URL dPoPJWKThumbprint;
    private final Scope scope;
}
