/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle.clientattestation;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.openid.connect.sdk.Nonce;
import de.bdr.pidp.issuer.base.jwt.JWKSecurityContext;
import de.bdr.pidp.issuer.base.jwt.StatusListRef;
import de.bdr.pidp.issuer.base.jwt.StatusListReferenceSecurityContext;
import de.bdr.pidp.issuer.base.jwt.X509SecurityContext;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.function.Predicate;

@NullMarked
@Getter
@RequiredArgsConstructor
class ClientAttestationSecurityContext implements X509SecurityContext, JWKSecurityContext, StatusListReferenceSecurityContext {

    private final Set<X509Certificate> trustAnchorCertificates;
    private final String clientId;

    @Nullable
    private final Predicate<Nonce> challengeCheck;

    @Setter
    @Nullable
    private JWK key;

    @Setter
    @Nullable
    private StatusListRef statusListRef;
}
