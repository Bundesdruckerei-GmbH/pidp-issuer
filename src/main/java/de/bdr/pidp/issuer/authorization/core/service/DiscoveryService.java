/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.id.Issuer;
import de.bdr.pidp.issuer.authorization.config.ReadOnlyAuthMetadata;
import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.authorization.in.DiscoveryPortIn;
import de.bdr.pidp.issuer.authorization.port.out.AccessTokenSigningPortOut;
import de.bdr.pidp.issuer.base.crypto.KeyID;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;

import java.util.List;

@NullMarked
@Component
public class DiscoveryService implements DiscoveryPortIn {

    private final ReadOnlyAuthMetadata metadata;
    private final AccessTokenSigningPortOut signatureProvider;
    private final KeyID signingAlias;

    public DiscoveryService(ReadOnlyAuthMetadata metadata, AccessTokenSigningPortOut signatureProvider, AuthorizationConfiguration config) {
        this.metadata = metadata;
        this.signatureProvider = signatureProvider;
        this.signingAlias = new KeyID(config.getAtSigAlias());
    }

    @Override
    public Issuer provideIssuer() {
        return metadata.getIssuer();
    }

    @Override
    public List<JWSAlgorithm> provideDPoPSigningAlgorithms() {
        return metadata.getDPoPJWSAlgs();
    }

    @Override
    public JWKSet provideJWKSet() {
        return new JWKSet(signatureProvider.getPublicKeys(signingAlias));
    }
}
