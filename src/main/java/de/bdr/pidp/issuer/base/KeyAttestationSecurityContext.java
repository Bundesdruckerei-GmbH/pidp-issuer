/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.openid.connect.sdk.Nonce;
import de.bdr.pidp.issuer.base.jwt.X509SecurityContext;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

@NullMarked
@Getter
@RequiredArgsConstructor
public class KeyAttestationSecurityContext implements X509SecurityContext {

    private final Set<X509Certificate> trustAnchorCertificates;
    @Nullable
    private final Predicate<@Nullable Nonce> nonceCheck;

    private final List<JWK> keys = new ArrayList<>();

    public void addKeys(List<JWK> keys) {
        this.keys.addAll(keys);
    }
}
