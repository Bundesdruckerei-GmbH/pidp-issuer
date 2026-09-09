/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.adapter.out;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.authorization.port.out.RefreshTokenSignerPortOut;
import de.bdr.pidp.issuer.base.KeyNotFoundException;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.crypto.KeyID;
import de.bdr.pidp.issuer.base.crypto.VersionedKeyID;
import de.bdr.pidp.issuer.base.crypto.hsm.HSMKeyAttributes;
import de.bdr.pidp.issuer.base.crypto.hsm.HSMSigningService;
import de.bdr.pidp.issuer.base.jwk.JWKUtils;
import de.bdr.pidp.issuer.base.jwk.LazyJWKSource;
import de.bdr.pidp.issuer.base.jwt.HashingRemoteSigner;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

@Component
@ConditionalOnProperty(name = "hsm.enabled", havingValue = "true")
public class HSMRefreshTokenSignerAdapter implements RefreshTokenSignerPortOut {

    private final KeyID keyID;
    private final HSMSigningService hsmSigningService;
    private final Map<VersionedKeyID, X509Certificate> certificates = new ConcurrentHashMap<>();

    public HSMRefreshTokenSignerAdapter(AuthorizationConfiguration configuration, HSMSigningService hsmSigningAuthorization) {
        keyID = new KeyID(configuration.getRtSigAliasHsm());
        this.hsmSigningService = hsmSigningAuthorization;
    }

    @Override
    public SigningContext signingContext() {
        var attr = hsmSigningService.getLatestVersionKeyAttributes(keyID);

        return new SigningContext(
            signer(attr),
            attr.algorithm(),
            attr.keyID().toString()
        );
    }

    @Override
    public <C extends SecurityContext> JWKSource<C> jwkSource() {
        Function<Set<String>, JWKSet> jwkSetFunction = kidSet -> {
            List<JWK> jwks = kidSet.stream()
                .map(this::createJwkFromKid)
                .filter(Objects::nonNull)
                .toList();
            return new JWKSet(jwks);
        };
        return new LazyJWKSource<>(jwkSetFunction);
    }

    private JWSSigner signer(HSMKeyAttributes attr) {
        return new HashingRemoteSigner(
            Set.of(attr.algorithm()),
            hash -> hsmSigningService.sign(attr.keyID(), hash)
        );
    }

    private @Nullable JWK createJwkFromKid(String kid) {
        X509Certificate cert;
        try {
            var vKid = VersionedKeyID.parse(kid);
            cert = findCertificate(vKid);
        } catch (KeyNotFoundException | IllegalArgumentException _) {
            return null;
        }
        try {
            JWK key = JWK.parse(cert);
            return JWKUtils.extendWithKeyID(key, kid);
        } catch (JOSEException e) {
            throw new PidServerException("certificate could not be parsed", e);
        }
    }

    private X509Certificate findCertificate(VersionedKeyID versionedKeyID) {
        return certificates.computeIfAbsent(versionedKeyID, hsmSigningService::getX509Certificate);
    }
}
