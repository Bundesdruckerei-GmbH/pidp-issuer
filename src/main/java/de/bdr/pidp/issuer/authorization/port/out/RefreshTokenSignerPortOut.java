/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.port.out;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

public interface RefreshTokenSignerPortOut {

    SigningContext signingContext();

    <C extends SecurityContext> JWKSource<C> jwkSource();

    record SigningContext(JWSSigner signer, JWSAlgorithm algorithm, String keyID) {
    }
}
