/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.out.hsm;

import com.nimbusds.jose.JWSAlgorithm;
import de.bdr.pidp.issuer.base.FileResourceHelper;
import de.bdr.pidp.issuer.base.crypto.KeyID;
import de.bdr.pidp.issuer.base.crypto.VersionedKeyID;
import de.bdr.pidp.issuer.base.crypto.hsm.HSMSigningService;
import de.bdr.pidp.issuer.issuance.config.IssuanceConfiguration;
import de.bdr.pidp.issuer.issuance.core.signer.Algorithm;
import de.bdr.pidp.issuer.issuance.core.signer.CredentialSigner;
import org.jspecify.annotations.NullMarked;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@NullMarked
@Component
@ConditionalOnProperty(name = "hsm.enabled", havingValue = "true")
class HSMCredentialSignerAdapter implements CredentialSigner {

    private final HSMSigningService hsmSigningService;
    private final KeyID keyID;
    private final Map<VersionedKeyID, X509Certificate> certificates = new ConcurrentHashMap<>();
    private final X509Certificate rootCertificate;

    HSMCredentialSignerAdapter(HSMSigningService hsmSigningIssuance, FileResourceHelper fileResourceHelper, IssuanceConfiguration config) {
        this.hsmSigningService = hsmSigningIssuance;
        this.keyID = new KeyID(config.getPidSigAliasHsm());
        rootCertificate = fileResourceHelper.readCertificate(config.getCaCertPath());
    }

    @Override
    public Algorithm getAlgorithm() {
        var attr = hsmSigningService.getLatestVersionKeyAttributes(keyID);

        return Arrays.stream(Algorithm.values())
            .filter(a -> a.getJwsAlgorithm().equals(attr.algorithm()))
            .findFirst().orElseThrow(() -> new IllegalStateException("No matching alg found"));
    }

    @Override
    public List<X509Certificate> getCertificateChain() {
        var versionedKeyID = hsmSigningService.getLatestVersionKeyAttributes(keyID).keyID();
        X509Certificate cert = certificates.computeIfAbsent(versionedKeyID, hsmSigningService::getX509Certificate);
        return List.of(cert, rootCertificate);
    }

    @Override
    public byte[] sign(byte[] data) {
        var attr = hsmSigningService.getLatestVersionKeyAttributes(keyID);

        var hashed = hash(data, attr.algorithm());
        return hsmSigningService.sign(attr.keyID(), hashed);
    }

    private byte[] hash(byte[] bytes, JWSAlgorithm alg) {
        String hashAlg;
        if (alg == JWSAlgorithm.ES256) {
            hashAlg = "SHA-256";
        } else if (alg == JWSAlgorithm.ES384) {
            hashAlg = "SHA-384";
        } else if (alg == JWSAlgorithm.ES512) {
            hashAlg = "SHA-512";
        } else {
            throw new IllegalStateException("Unsupported JWS algorithm");
        }

        MessageDigest md;
        try {
            md = MessageDigest.getInstance(hashAlg);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unsupported hash algorithm: " + e.getMessage(), e);
        }

        return md.digest(bytes);
    }
}
