/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service;

import com.nimbusds.jose.jwk.JWKSet;
import de.bdr.pidp.issuer.issuance.config.model.RequestEncryptionJWKSupplier;
import de.bdr.pidp.issuer.issuance.openid4vci.out.kms.KMSRequestEncryptionKeyAdapter;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;

@NullMarked
@Component
@RequiredArgsConstructor
public class RequestEncryptionService implements RequestEncryptionJWKSupplier {
    private final KMSRequestEncryptionKeyAdapter requestEncryptionAdapter;

    @Override
    public JWKSet jwks() {
        return new JWKSet(requestEncryptionAdapter.getLatestPublicKey());
    }

    public JWKSet getPrivateKeySet() {
        return new JWKSet(requestEncryptionAdapter.getPrivateKeys());
    }
}
