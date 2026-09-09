/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance;

import de.bdr.pidp.issuer.issuance.config.IssuanceConfiguration;
import de.bdr.pidp.issuer.issuance.config.MetadataSignerConfiguration;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.testdata.TestConfig;

import java.net.MalformedURLException;
import java.net.URI;
import java.time.Duration;
import java.time.Period;
import java.util.List;

public class ConfigTestData {
    public static final IssuanceConfiguration ISSUANCE_CONFIG;
    public static final MetadataSignerConfiguration METADATA_SIGNER_CONFIG = new MetadataSignerConfiguration();

    static {
        ISSUANCE_CONFIG = new IssuanceConfiguration();
        ISSUANCE_CONFIG.setProcessRealData(false);
        ISSUANCE_CONFIG.setLifetime(Duration.ofDays(14L));
        ISSUANCE_CONFIG.setMaxValidity(Period.ofYears(5));
        ISSUANCE_CONFIG.setSignerPath("issuance/issuer-localhost.p12");
        ISSUANCE_CONFIG.setSignerPassword("Miereimuw1aehaewohh2");
        ISSUANCE_CONFIG.setSignerAlias("1");
        ISSUANCE_CONFIG.setProofTimeTolerance(Duration.ofSeconds(60));
        ISSUANCE_CONFIG.setBatchIssuanceMaxSize(10);
        ISSUANCE_CONFIG.setCNonceLifetime(Duration.ofMinutes(60));
        ISSUANCE_CONFIG.setProofValidity(Duration.ofSeconds(60));
        ISSUANCE_CONFIG.setSupportedConfigurationIds(List.of(
            CredentialConfigurationID.SD_JWT_V1,
            CredentialConfigurationID.SD_JWT_V2,
            CredentialConfigurationID.SD_JWT_V3_BETA,
            CredentialConfigurationID.MSO_MDOC_V1,
            CredentialConfigurationID.MSO_MDOC_V2,
            CredentialConfigurationID.MSO_MDOC_V3_BETA));
        try {
            ISSUANCE_CONFIG.setBaseUrl(URI.create(TestConfig.pidiBaseUrl()).toURL());
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
        ISSUANCE_CONFIG.setPidSigAliasHsm("pp_pid_auth");
        ISSUANCE_CONFIG.setCaCertPath("issuance/cacert.pem");

        METADATA_SIGNER_CONFIG.setSignerAlias("metadata-test");
        METADATA_SIGNER_CONFIG.setSignerPassword("metadata-test");
        METADATA_SIGNER_CONFIG.setSignerPath("metadata/metadata-test.p12");
        METADATA_SIGNER_CONFIG.setAccessCertificateAlias("access-certificate");
    }
}
