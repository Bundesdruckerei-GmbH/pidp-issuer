/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.adapter.out;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import de.bdr.pidp.issuer.base.KeyNotFoundException;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.crypto.KeyID;
import de.bdr.pidp.issuer.base.crypto.VersionedKeyID;
import de.bdr.pidp.issuer.base.crypto.hsm.HSMKeyAttributes;
import de.bdr.pidp.issuer.base.crypto.hsm.HSMSigningService;
import de.bdr.pidp.issuer.base.jwk.JWKUtils;
import de.bdr.pidp.issuer.base.jwk.LazyJWKSource;
import de.bdr.pidp.issuer.base.jwt.HashingRemoteSigner;
import de.bdr.pidp.issuer.identification.config.IdentificationConfiguration;
import de.bdr.pidp.issuer.identification.port.out.SeedCredentialSignerPortOut;
import org.jspecify.annotations.NullMarked;
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

@NullMarked
@Component
@ConditionalOnProperty(name = "hsm.enabled", havingValue = "true")
class HSMSeedCredentialSignerAdapter implements SeedCredentialSignerPortOut {

    private final HSMSigningService hsmSigningService;
    private final KeyID keyID;
    private final Map<VersionedKeyID, X509Certificate> certificates = new ConcurrentHashMap<>();

    HSMSeedCredentialSignerAdapter(IdentificationConfiguration configuration,
                                   HSMSigningService hsmSigningIdentification) {
        this.hsmSigningService = hsmSigningIdentification;
        this.keyID = new KeyID(configuration.getSeedSigAliasHsm());
    }

    @Override
    public SigningContext signingContext() {
        var attr = hsmSigningService.getLatestVersionKeyAttributes(keyID);

        return new SigningContext(
            signer(attr),
            findCertificate(attr.keyID()),
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
            throw new PidServerException("Certificate could not be parsed", e);
        }
    }

    private X509Certificate findCertificate(VersionedKeyID versionedKeyID) {
        return certificates.computeIfAbsent(versionedKeyID, hsmSigningService::getX509Certificate);
    }

    private JWSSigner signer(HSMKeyAttributes attr) {
        return new HashingRemoteSigner(
            Set.of(attr.algorithm()),
            hash -> hsmSigningService.sign(attr.keyID(), hash)
        );
    }
}
