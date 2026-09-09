/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.base.FileResourceHelper;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.crypto.KeyID;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.security.KeyStore;
import java.security.KeyStoreException;

/**
 * Will be removed when the HSM is integrated for refresh token signing
 */
@NullMarked
@Component
@ConditionalOnProperty(name = "hsm.enabled", havingValue = "false")
public class TemporarySignerProvider {

    private final String signatureAlias;
    private final String signerPassword;

    private final KeyStore keystore;

    public TemporarySignerProvider(
        AuthorizationConfiguration config,
        FileResourceHelper helper
    ) {
        this.signatureAlias = config.getRtSigAlias();
        this.signerPassword = config.getRtPassword();
         var signerPath = config.getRtPath();
        this.keystore = helper.readKeyStore(signerPath, signerPassword);
    }

    public KeyID currentKeyID() {
        return new KeyID(signatureAlias);
    }

    public JWSSigner currentSigner() {
        try {
            ECKey key = ECKey.load(keystore, signatureAlias, signerPassword.toCharArray());
            return new ECDSASigner(key);
        } catch (IllegalArgumentException | KeyStoreException | JOSEException e) {
            throw new PidServerException("Could not load keystore", e);
        }
    }

    @Nullable
    public ECKey findPublicKey(KeyID keyID) {
        try {
            ECKey key = ECKey.load(keystore, keyID.value(), signerPassword.toCharArray());
            return key == null ? null : key.toPublicJWK();
        } catch (IllegalArgumentException | KeyStoreException | JOSEException e) {
            throw new PidServerException("Could not load keystore", e);
        }
    }
}
