/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service;

import de.bdr.pidp.issuer.issuance.config.IssuanceConfiguration;
import de.bdr.pidp.issuer.issuance.config.IssuanceTestMetadata;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.UnknownCredentialConfigurationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.util.List;

import static de.bdr.pidp.issuer.issuance.ConfigTestData.ISSUANCE_CONFIG;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CredentialConfigurationIDValidatorTest {
    private final List<CredentialConfigurationID> supported = List.of(CredentialConfigurationID.SD_JWT_V1);
    private CredentialConfigurationIDValidator subject;

    @BeforeEach
    void setUp() throws MalformedURLException {
        var config = new IssuanceConfiguration();
        config.setBaseUrl(ISSUANCE_CONFIG.getBaseUrl());
        config.setSupportedConfigurationIds(supported);
        var metadata = IssuanceTestMetadata.createCredentialIssuerMetadata(config);
        subject = new CredentialConfigurationIDValidator(metadata);
    }

    @Test
    void supported() {
        assertThatNoException().isThrownBy(() -> subject.validate(CredentialConfigurationID.SD_JWT_V1));
    }

    @Test
    void unsupported() {
        assertThatThrownBy(() -> subject.validate(CredentialConfigurationID.MSO_MDOC_V1))
            .isInstanceOf(UnknownCredentialConfigurationException.class);
    }
}
