/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwk;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Set;
import java.util.function.Function;

public class LazyJWKSource<C extends SecurityContext> implements JWKSource<C> {

    private final Function<Set<String>, JWKSet> supplier;

    @Nullable
    private JWKSet jwkSet;

    /**
     * @param supplier provides a set of keyIDs and requires {@link JWKSet} to be returned
     */
    public LazyJWKSource(Function<Set<String>, JWKSet> supplier) {
        this.supplier = supplier;
    }

    @Override
    public synchronized List<JWK> get(JWKSelector jwkSelector, C c) throws KeySourceException {
        if (jwkSet != null) {
            var selectedKeys = jwkSelector.select(jwkSet);
            if (!selectedKeys.isEmpty()) {
                return selectedKeys;
            }
            jwkSet = null;
        }

        var kids = jwkSelector.getMatcher().getKeyIDs();
        jwkSet = supplier.apply(kids);
        return jwkSelector.select(jwkSet);
    }
}
