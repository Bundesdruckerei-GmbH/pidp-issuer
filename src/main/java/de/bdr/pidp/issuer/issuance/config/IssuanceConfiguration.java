/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.config;

import de.bdr.pidp.issuer.base.BaseUrlConfiguration;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.time.Period;
import java.util.List;

@Setter
@Getter
@Validated
@Configuration
@ConfigurationProperties(prefix = "pidi.issuance")
public class IssuanceConfiguration extends BaseUrlConfiguration {
    private boolean processRealData;
    private String signerPath;
    private String signerPassword;
    private String signerAlias;
    private String caCertPath;
    private String pidSigAliasHsm;
    private Duration lifetime;
    private Period maxValidity;
    private int batchIssuanceMaxSize;
    private Duration proofTimeTolerance;
    /**
     * lifetime of a c_nonce
     */
    private Duration cNonceLifetime;
    private Duration proofValidity;

    private List<CredentialConfigurationID> supportedConfigurationIds;

    private String creqEncKaAlias;

    private KMS kms;

    @Getter
    @Setter
    public static class KMS {

        private String transitPath;
    }

    public boolean allowSelfSignedAttestationCert() {
        return !processRealData;
    }
}
