/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.port.out;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.jspecify.annotations.NullMarked;

import java.security.cert.X509Certificate;

@NullMarked
public interface SeedCredentialSignerPortOut {

    SigningContext signingContext();

    <C extends SecurityContext> JWKSource<C> jwkSource();

    record SigningContext(JWSSigner signer, X509Certificate cert, JWSAlgorithm algorithm, String keyID) {
    }
}
