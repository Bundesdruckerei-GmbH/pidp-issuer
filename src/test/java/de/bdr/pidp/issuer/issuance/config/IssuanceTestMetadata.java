/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.config;

import com.nimbusds.jose.jwk.JWKSet;
import de.bdr.pidp.issuer.issuance.ConfigTestData;
import de.bdr.pidp.issuer.issuance.config.model.CredentialIssuerMetadata;
import de.bdr.pidp.issuer.issuance.config.model.RequestEncryptionJWKSupplier;
import de.bdr.pidp.issuer.testdata.TestUtils;

public class IssuanceTestMetadata {

    private static final RequestEncryptionJWKSupplier JWK_SUPPLIER = () -> new JWKSet(TestUtils.REQUEST_ENCRYPTION_PUB);
    public static final CredentialIssuerMetadata ISSUANCE_METADATA = new PIDCredentialMetadataConfiguration().readOnlyCredMetadata(ConfigTestData.ISSUANCE_CONFIG, JWK_SUPPLIER);
    public static CredentialIssuerMetadata createCredentialIssuerMetadata(IssuanceConfiguration issuanceConfiguration) {
        return new PIDCredentialMetadataConfiguration().readOnlyCredMetadata(issuanceConfiguration, JWK_SUPPLIER);
    }
}
