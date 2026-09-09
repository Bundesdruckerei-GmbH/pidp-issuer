/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.config;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Issuer;
import de.bdr.pidp.issuer.issuance.config.model.AttackPotentialResistance;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfiguration;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationImpl;
import de.bdr.pidp.issuer.issuance.config.model.CredentialIssuerMetadata;
import de.bdr.pidp.issuer.issuance.config.model.CredentialIssuerMetadataImpl;
import de.bdr.pidp.issuer.issuance.config.model.CredentialMetadata;
import de.bdr.pidp.issuer.issuance.config.model.CredentialMetadataImpl;
import de.bdr.pidp.issuer.issuance.config.model.CredentialRequestEncryption;
import de.bdr.pidp.issuer.issuance.config.model.CredentialRequestEncryptionImpl;
import de.bdr.pidp.issuer.issuance.config.model.CredentialResponseEncryption;
import de.bdr.pidp.issuer.issuance.config.model.CredentialResponseEncryptionImpl;
import de.bdr.pidp.issuer.issuance.config.model.CryptographicBindingMethod;
import de.bdr.pidp.issuer.issuance.config.model.ProofType;
import de.bdr.pidp.issuer.issuance.config.model.ProofTypeImpl;
import de.bdr.pidp.issuer.issuance.config.model.RequestEncryptionJWKSupplier;
import de.bdr.pidp.issuer.issuance.config.model.SupportedProofType;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@NullMarked
@Configuration
class PIDCredentialMetadataConfiguration {

    private static final Scope SCOPE = new Scope("pid");
    private static final String FORMAT_SD_JWT = "dc+sd-jwt";
    private static final String FORMAT_MDOC = "mso_mdoc";
    private static final String VCT = "urn:eudi:pid:de:1";
    private static final String DOCTYPE = "eu.europa.ec.eudi.pid.1";

    @Bean
    CredentialIssuerMetadata readOnlyCredMetadata(IssuanceConfiguration configuration, RequestEncryptionJWKSupplier jwkSupplier) {
        var issuerUrl = configuration.getCredentialIssuerIdentifier();
        var iss = new Issuer(issuerUrl);
        var cEndpoint = URI.create(issuerUrl + "/credential");
        var ccSupported = buildCredentialConfigurationsSupported(configuration.getSupportedConfigurationIds());
        var cm = new CredentialIssuerMetadataImpl(iss, cEndpoint, ccSupported);
        cm.nonceEndpoint(URI.create(issuerUrl + "/nonce"));
        var reqEnc = credentialRequestEncryption(jwkSupplier);
        cm.credentialRequestEncryption(reqEnc);
        var resEnc = credentialResponseEncryption();
        cm.credentialResponseEncryption(resEnc);
        var batch = new CredentialIssuerMetadataImpl.BatchCredentialIssuance(configuration.getBatchIssuanceMaxSize());
        cm.batchCredentialIssuance(batch);
        var displays = loadIssuerDisplays();
        cm.displays(displays);

        return cm;
    }

    private static CredentialRequestEncryption credentialRequestEncryption(RequestEncryptionJWKSupplier jwkSupplier) {
        return new CredentialRequestEncryptionImpl(jwkSupplier, List.of(EncryptionMethod.A256GCM), false);
    }

    private static CredentialResponseEncryption credentialResponseEncryption() {
        return new CredentialResponseEncryptionImpl(List.of(JWEAlgorithm.ECDH_ES), List.of(EncryptionMethod.A256GCM), false);
    }

    private Map<CredentialConfigurationID, CredentialConfiguration> buildCredentialConfigurationsSupported(List<CredentialConfigurationID> supportedConfigurationIDs) {
        var metadataMap = loadCredentialMetadata();
        return supportedConfigurationIDs.stream().collect(Collectors.toMap(c -> c, c -> switch (c) {
            case SD_JWT_V1, SD_JWT_V2, SD_JWT_V3_BETA -> sdJwtCredentialConfiguration(metadataMap.get(c.getName()));
            case MSO_MDOC_V1, MSO_MDOC_V2, MSO_MDOC_V3_BETA -> mdocCredentialConfiguration(metadataMap.get(c.getName()));
        }, (c, _) -> c, LinkedHashMap::new)); // LinkedHashMap to keep the order of configured credential configurations
    }

    private static CredentialConfiguration sdJwtCredentialConfiguration(@Nullable CredentialMetadata credentialMetadata) {
        var cc = new CredentialConfigurationImpl.SdJwt(FORMAT_SD_JWT, VCT);
        cc.scope(SCOPE);
        cc.credentialSigningAlgValuesSupported(List.of(JWSAlgorithm.ES256));
        cc.cryptographicBinding(List.of(CryptographicBindingMethod.JWK), Map.of(
            SupportedProofType.JWT, jwtProofType(),
            SupportedProofType.ATTESTATION, attestationProofType()
        ));
        if (credentialMetadata != null) {
            cc.credentialMetadata(credentialMetadata);
        }
        return cc;
    }

    private static CredentialConfiguration mdocCredentialConfiguration(@Nullable CredentialMetadata credentialMetadata) {
        var cc = new CredentialConfigurationImpl.Mdoc(FORMAT_MDOC, DOCTYPE);
        cc.scope(SCOPE);
        cc.credentialSigningAlgValuesSupported(List.of(JWSAlgorithm.ES256));
        cc.cryptographicBinding(List.of(CryptographicBindingMethod.COSE_KEY), Map.of(
            SupportedProofType.JWT, jwtProofType(),
            SupportedProofType.ATTESTATION, attestationProofType()
        ));
        if (credentialMetadata != null) {
            cc.credentialMetadata(credentialMetadata);
        }
        return cc;
    }

    private static ProofType jwtProofType() {
        return new ProofTypeImpl(List.of(JWSAlgorithm.ES256));
    }

    private static ProofType attestationProofType() {
        var pt = new ProofTypeImpl(List.of(JWSAlgorithm.ES256));
        var kar = new ProofTypeImpl.KeyAttestationsRequired();
        kar.keyStorage(List.of(AttackPotentialResistance.ISO_18045_HIGH));
        kar.userAuthentication(List.of(AttackPotentialResistance.ISO_18045_HIGH));
        pt.keyAttestationsRequired(kar);
        return pt;
    }

    private List<CredentialIssuerMetadata.Display> loadIssuerDisplays() {
        var module = new SimpleModule()
            .addAbstractTypeMapping(CredentialIssuerMetadata.Display.class, CredentialIssuerMetadataImpl.Display.class);
        return loadYamlContents("/metadata/credential_issuer_displays.yaml", module, new TypeReference<>() {});
    }

    private Map<String, CredentialMetadata> loadCredentialMetadata() {
        var module = new SimpleModule()
                .addAbstractTypeMapping(CredentialMetadata.class, CredentialMetadataImpl.class)
                .addAbstractTypeMapping(CredentialMetadata.Claim.class, CredentialMetadataImpl.Claim.class)
                .addAbstractTypeMapping(CredentialMetadata.Display.class, CredentialMetadataImpl.Display.class);
        return loadYamlContents("/metadata/credential_metadata.yaml", module, new TypeReference<>() {});
    }

    private <T> T loadYamlContents(String resourcePath, Module mappingModule, TypeReference<T> typeReference) {
        var ym = YAMLMapper.builder()
            .addModule(mappingModule)
            .enable(
                DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,
                DeserializationFeature.FAIL_ON_NULL_CREATOR_PROPERTIES,
                DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES)
            .build();
        ym.findAndRegisterModules();
        var input = PIDCredentialMetadataConfiguration.class.getResourceAsStream(resourcePath);
        try {
            return ym.readValue(input, typeReference);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
