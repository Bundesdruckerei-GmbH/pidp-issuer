/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.signer;

import com.nimbusds.jose.JOSEException;
import de.bdr.pidp.issuer.base.FileResourceHelper;
import de.bdr.pidp.issuer.issuance.config.MetadataSignerConfiguration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import static de.bdr.pidp.issuer.issuance.ConfigTestData.METADATA_SIGNER_CONFIG;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class MetadataSignerTest {

    private final FileResourceHelper fileResourceHelper = new FileResourceHelper();
    @Spy
    private MetadataSignerConfiguration metadataConfig = METADATA_SIGNER_CONFIG;

    @Test
    void metadataSignerCreated() {
        var metadataSigner = new MetadataSigner(fileResourceHelper, metadataConfig);
        assertThat(metadataSigner).isNotNull();
    }

    @Test
    void credentialMetadataJwtECKeyNotFoundInKeyStore() {
        when(metadataConfig.getSignerAlias()).thenReturn("2");
        assertThatThrownBy(() -> new MetadataSigner(fileResourceHelper, metadataConfig)).hasMessage("Metadata keystore could not be loaded: Key not found in keystore.");
    }

    @Test
    void credentialMetadataJwtFalseKeyStore() {
        when(metadataConfig.getSignerPath()).thenReturn("src/test/resources/keystore/rsa-keypair-test.p12");
        when(metadataConfig.getSignerPassword()).thenReturn("rsa-keypair-test");
        when(metadataConfig.getSignerAlias()).thenReturn("rsa-keypair-test");
        assertThatThrownBy(() -> new MetadataSigner(fileResourceHelper, metadataConfig)).hasMessage("Metadata keystore could not be loaded.")
            .hasCauseInstanceOf(JOSEException.class).cause().hasMessageContaining("The key algorithm is not EC");
    }

    @Test
    void credentialMetadataJwtFalseCurve() {
        when(metadataConfig.getSignerPath()).thenReturn("src/test/resources/keystore/metadata-test-384.p12");
        when(metadataConfig.getSignerAlias()).thenReturn("metadata-test-384");
        assertThatThrownBy(() -> new MetadataSigner(fileResourceHelper, metadataConfig)).hasMessage("Metadata keystore could not be loaded: Key is not EC256 key.");
    }
}
