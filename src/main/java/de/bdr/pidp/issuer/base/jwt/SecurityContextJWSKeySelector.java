/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.proc.JWSKeySelector;
import de.bdr.pidp.issuer.base.jwk.JWKUtils;
import lombok.val;

import java.security.Key;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public class SecurityContextJWSKeySelector<C extends JWKSecurityContext> implements JWSKeySelector<C> {
    private final Set<JWSAlgorithm> jwsAlgorithmsSupported;

    public SecurityContextJWSKeySelector(Set<JWSAlgorithm> jwsAlgorithmsSupported) {
        this.jwsAlgorithmsSupported = jwsAlgorithmsSupported;
    }

    @Override
    public List<? extends Key> selectJWSKeys(JWSHeader header, C context) throws KeySourceException {

        if (!jwsAlgorithmsSupported.contains(header.getAlgorithm())) {
            return Collections.emptyList();
        }

        val key = context.getKey();

        if (key == null) {
            return Collections.emptyList();
        }

        try {
            return List.of(JWKUtils.toPublicKey(key));
        } catch (JOSEException e) {
            throw new KeySourceException("Invalid JWK", e);
        }
    }
}
