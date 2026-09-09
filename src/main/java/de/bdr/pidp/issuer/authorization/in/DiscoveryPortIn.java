/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.in;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.id.Issuer;
import org.jspecify.annotations.NullMarked;

import java.util.List;

@NullMarked
public interface DiscoveryPortIn {

    Issuer provideIssuer();
    List<JWSAlgorithm> provideDPoPSigningAlgorithms();
    JWKSet provideJWKSet();
}
