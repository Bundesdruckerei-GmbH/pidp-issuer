/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service;

import com.nimbusds.jose.jwk.JWK;
import de.bdr.pidp.issuer.issuance.config.IssuanceConfiguration;
import de.bdr.pidp.issuer.issuance.core.signer.PKCS12CredentialSigner;
import de.bdr.pidp.issuer.issuance.core.signer.CredentialSigner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Collection;

import static de.bdr.pidp.issuer.issuance.ConfigTestData.ISSUANCE_CONFIG;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class MetadataServiceTest {

    @Spy
    IssuanceConfiguration configuration = ISSUANCE_CONFIG;

    CredentialSigner credentialSigner = new PKCS12CredentialSigner(configuration);

    MetadataServiceTest() throws UnrecoverableKeyException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
    }

    @Test
    void shouldProcess() {
        MetadataService metadataService = new MetadataService(credentialSigner);

        Collection<JWK> jwks = metadataService.getJWKs();
        assertThat(jwks).hasSize(1);
    }
}
