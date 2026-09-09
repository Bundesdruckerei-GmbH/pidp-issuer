/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwt;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyConverter;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import org.jspecify.annotations.Nullable;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

public class JWEDecryptionKeySelector<C extends SecurityContext> implements JWEKeySelector<@Nullable C> {

    private final List<EncryptionMethod> jweEncs;
    private final JWKSource<@Nullable C> jwkSource;

    public JWEDecryptionKeySelector(List<EncryptionMethod> jweEncs, JWKSource<C> jwkSource) {
        this.jweEncs = jweEncs;
        this.jwkSource = jwkSource;
    }

    @Override
    public List<Key> selectJWEKeys(final JWEHeader jweHeader, @Nullable final C context)
        throws KeySourceException {

        if (!jweEncs.contains(jweHeader.getEncryptionMethod())) {
            throw new KeySourceException("Unsupported encryption method");
        }

        JWKMatcher jwkMatcher = createJWKMatcher(jweHeader);
        List<JWK> jwkMatches = jwkSource.get(new JWKSelector(jwkMatcher), context);
        List<JWK> filteredJwkMatches = jwkMatches.stream().filter(jwk -> Objects.equals(jwk.getKeyID(), jweHeader.getKeyID())).toList();
        List<Key> sanitizedKeyList = new LinkedList<>();

        for (Key key : KeyConverter.toJavaKeys(filteredJwkMatches)) {
            if (key instanceof PrivateKey || key instanceof SecretKey) {
                sanitizedKeyList.add(key);
            } // skip public keys
        }

        if (sanitizedKeyList.isEmpty()) {
            throw new KeySourceException("No matching keys found");
        }

        return sanitizedKeyList;
    }

    private JWKMatcher createJWKMatcher(final JWEHeader jweHeader) {
        return new JWKMatcher.Builder()
            .keyType(KeyType.forAlgorithm(jweHeader.getAlgorithm()))
            .keyID(jweHeader.getKeyID())
            .withKeyIDOnly(true)
            .keyUses(KeyUse.ENCRYPTION)
            .algorithms(jweHeader.getAlgorithm())
            .build();
    }
}
