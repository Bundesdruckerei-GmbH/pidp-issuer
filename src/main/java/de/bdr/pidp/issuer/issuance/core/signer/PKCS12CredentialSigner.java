/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.signer;

import com.nimbusds.jose.jwk.Curve;
import de.bdr.pidp.issuer.base.FileResourceHelper;
import de.bdr.pidp.issuer.issuance.config.IssuanceConfiguration;
import org.jspecify.annotations.NullMarked;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@NullMarked
@ConditionalOnProperty(name = "hsm.enabled", havingValue = "false")
@Component
public class PKCS12CredentialSigner extends JcaKeyBasedCredentialSigner {
    private final PrivateKey privateKey;
    private final List<X509Certificate> chain;

    @Autowired
    public PKCS12CredentialSigner(IssuanceConfiguration config) throws IOException, UnrecoverableKeyException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        this(FileResourceHelper.getFileInputStream(config.getSignerPath()), config.getSignerPassword());
    }

    public PKCS12CredentialSigner(InputStream keystore, String password) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        var ks = KeyStore.getInstance("pkcs12");
        ks.load(keystore, password.toCharArray());

        var aliases = Collections.list(ks.aliases());
        if (aliases.size() != 1) {
            throw new IllegalArgumentException("Expected a keystore with a key entry");
        }

        privateKey = (PrivateKey) ks.getKey(aliases.getFirst(), password.toCharArray());
        if (privateKey == null) {
            throw new IllegalArgumentException("Expected a keystore with a key entry");
        }

        var certChain = ks.getCertificateChain(aliases.getFirst());
        if (certChain == null) {
            throw new IllegalArgumentException("Expected a keystore with a certificate chain");
        }

        chain = new ArrayList<>();
        for (Certificate cert : certChain) {
            chain.add((X509Certificate) cert);
        }
    }

    @Override
    public List<X509Certificate> getCertificateChain() {
        return chain;
    }

    @Override
    public JcaKeyBasedCredentialSigner.SupportedAlgorithm getSupportedAlgorithm() {
        return algorithm(chain.getFirst());
    }

    private static JcaKeyBasedCredentialSigner.SupportedAlgorithm algorithm(X509Certificate cert) {
        var curve = Curve.forECParameterSpec(((ECKey) cert.getPublicKey()).getParams());
        for (var algo : JcaKeyBasedCredentialSigner.SupportedAlgorithm.getEntries()) {
            if (algo.getCurve().equals(curve)) {
                return algo;
            }
        }
        throw new IllegalArgumentException("Unsupported curve " + curve);
    }

    @Override
    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}
