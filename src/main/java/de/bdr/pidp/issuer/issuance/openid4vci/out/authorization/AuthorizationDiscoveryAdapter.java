/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.out.authorization;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.id.Issuer;
import de.bdr.pidp.issuer.authorization.in.DiscoveryPortIn;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;

import java.util.List;

@NullMarked
@Component
public class AuthorizationDiscoveryAdapter {

    private final DiscoveryPortIn discovery;

    public AuthorizationDiscoveryAdapter(DiscoveryPortIn discovery) {
        this.discovery = discovery;
    }

    public Issuer getIssuer() {
        return discovery.provideIssuer();
    }

    public List<JWSAlgorithm> getDPoPSigningAlgorithms() {
        return discovery.provideDPoPSigningAlgorithms();
    }

    public JWKSet getJWKSet() {
        return discovery.provideJWKSet();
    }
}
