/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.config;

import de.bdr.pidp.issuer.issuance.config.model.CredentialConfiguration;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.config.model.CredentialIssuerMetadata;
import de.bdr.pidp.issuer.issuance.core.service.CredentialCreator;
import de.bdr.pidp.issuer.issuance.core.service.MdocCredentialCreatorV1;
import de.bdr.pidp.issuer.issuance.core.service.MdocCredentialCreatorV2;
import de.bdr.pidp.issuer.issuance.core.service.MdocCredentialCreatorV3Beta;
import de.bdr.pidp.issuer.issuance.core.service.SdJwtCredentialCreatorV1;
import de.bdr.pidp.issuer.issuance.core.service.SdJwtCredentialCreatorV2;
import de.bdr.pidp.issuer.issuance.core.service.SdJwtCredentialCreatorV3Beta;
import de.bdr.pidp.issuer.issuance.core.signer.CredentialSigner;
import org.jspecify.annotations.Nullable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Period;
import java.util.EnumMap;
import java.util.Map;

@Configuration
public class PidDataBuilderConfig {

    private final String authority;
    private final Period maxValidity;

    private final CredentialIssuerMetadata metadata;

    public PidDataBuilderConfig(IssuanceConfiguration configuration, CredentialIssuerMetadata metadata) {
        authority = configuration.getBaseUrl().toString();
        maxValidity = configuration.getMaxValidity();
        this.metadata = metadata;
    }

    @Bean
    public SdJwtCredentialCreatorV1 sdJwtCreatorV1(CredentialSigner signer) {
        var credentialConfiguration = metadata.credentialConfigurationsSupported().get(CredentialConfigurationID.SD_JWT_V1);
        if (credentialConfiguration instanceof CredentialConfiguration.SdJwt sdJwt) {
            return new SdJwtCredentialCreatorV1(authority, signer, sdJwt.vct(), sdJwt.format());
        }
        return null;
    }

    @Bean
    public SdJwtCredentialCreatorV2 sdJwtCreatorV2(CredentialSigner signer) {
        var credentialConfiguration = metadata.credentialConfigurationsSupported().get(CredentialConfigurationID.SD_JWT_V2);
        if (credentialConfiguration instanceof CredentialConfiguration.SdJwt sdJwt) {
            return new SdJwtCredentialCreatorV2(authority, signer, maxValidity, sdJwt.vct(), sdJwt.format());
        }
        return null;
    }

    @Bean
    public SdJwtCredentialCreatorV3Beta sdJwtCreatorV3Beta(CredentialSigner signer) {
        var credentialConfiguration = metadata.credentialConfigurationsSupported().get(CredentialConfigurationID.SD_JWT_V3_BETA);
        if (credentialConfiguration instanceof CredentialConfiguration.SdJwt sdJwt) {
            return new SdJwtCredentialCreatorV3Beta(authority, signer, sdJwt.vct(), sdJwt.format());
        }
        return null;
    }

    @Bean
    public MdocCredentialCreatorV1 mdocCreatorV1(CredentialSigner signer) {
        var credentialConfiguration = metadata.credentialConfigurationsSupported().get(CredentialConfigurationID.MSO_MDOC_V1);
        if (credentialConfiguration instanceof CredentialConfiguration.Mdoc mdoc) {
            return new MdocCredentialCreatorV1(signer, mdoc.doctype());
        }
        return null;
    }

    @Bean
    public MdocCredentialCreatorV2 mdocCreatorV2(CredentialSigner signer) {
        var credentialConfiguration = metadata.credentialConfigurationsSupported().get(CredentialConfigurationID.MSO_MDOC_V2);
        if (credentialConfiguration instanceof CredentialConfiguration.Mdoc mdoc) {
            return new MdocCredentialCreatorV2(signer, maxValidity, mdoc.doctype());
        }
        return null;
    }

    @Bean
    public MdocCredentialCreatorV3Beta mdocCreatorV3Beta(CredentialSigner signer) {
        var credentialConfiguration = metadata.credentialConfigurationsSupported().get(CredentialConfigurationID.MSO_MDOC_V3_BETA);
        if (credentialConfiguration instanceof CredentialConfiguration.Mdoc mdoc) {
            return new MdocCredentialCreatorV3Beta(signer, mdoc.doctype());
        }
        return null;
    }

    @Bean
    public Map<CredentialConfigurationID, CredentialCreator> credentialCreators(
        @Nullable SdJwtCredentialCreatorV1 sdJwtCreatorV1,
        @Nullable SdJwtCredentialCreatorV2 sdJwtCreatorV2,
        @Nullable SdJwtCredentialCreatorV3Beta sdJwtCreatorV3Beta,
        @Nullable MdocCredentialCreatorV1 mdocCreatorV1,
        @Nullable MdocCredentialCreatorV2 mdocCreatorV2,
        @Nullable MdocCredentialCreatorV3Beta mdocCreatorV3Beta
    ) {

        EnumMap<CredentialConfigurationID, CredentialCreator> creators = new EnumMap<>(CredentialConfigurationID.class);

        if (sdJwtCreatorV1 != null) {
            creators.put(CredentialConfigurationID.SD_JWT_V1, sdJwtCreatorV1);
        }
        if (sdJwtCreatorV2 != null) {
            creators.put(CredentialConfigurationID.SD_JWT_V2, sdJwtCreatorV2);
        }
        if (sdJwtCreatorV3Beta != null) {
            creators.put(CredentialConfigurationID.SD_JWT_V3_BETA, sdJwtCreatorV3Beta);
        }
        if (mdocCreatorV1 != null) {
            creators.put(CredentialConfigurationID.MSO_MDOC_V1, mdocCreatorV1);
        }
        if (mdocCreatorV2 != null) {
            creators.put(CredentialConfigurationID.MSO_MDOC_V2, mdocCreatorV2);
        }
        if (mdocCreatorV3Beta != null) {
            creators.put(CredentialConfigurationID.MSO_MDOC_V3_BETA, mdocCreatorV3Beta);
        }

        return creators;
    }
}
