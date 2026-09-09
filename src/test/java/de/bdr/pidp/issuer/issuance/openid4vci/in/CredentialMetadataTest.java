/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.in;

import com.nimbusds.jose.jwk.JWK;
import de.bdr.pidp.issuer.base.FileResourceHelper;
import de.bdr.pidp.issuer.issuance.IdentityDataBase;
import de.bdr.pidp.issuer.issuance.config.MetadataSignerConfiguration;
import de.bdr.pidp.issuer.issuance.config.PidDataBuilderConfig;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.config.model.CredentialIssuerMetadata;
import de.bdr.pidp.issuer.issuance.core.StatusReference;
import de.bdr.pidp.issuer.issuance.core.service.CredentialCreator;
import de.bdr.pidp.issuer.issuance.core.service.MdocCredentialCreatorV1;
import de.bdr.pidp.issuer.issuance.core.service.MdocCredentialCreatorV2;
import de.bdr.pidp.issuer.issuance.core.service.MdocCredentialCreatorV3Beta;
import de.bdr.pidp.issuer.issuance.core.service.PIDIdentityData;
import de.bdr.pidp.issuer.issuance.core.service.PIDIdentityDataBuilder;
import de.bdr.pidp.issuer.issuance.core.service.SdJwtCredentialCreatorV1;
import de.bdr.pidp.issuer.issuance.core.service.SdJwtCredentialCreatorV2;
import de.bdr.pidp.issuer.issuance.core.service.SdJwtCredentialCreatorV3Beta;
import de.bdr.pidp.issuer.issuance.core.signer.PKCS12CredentialSigner;
import de.bdr.pidp.issuer.issuance.openid4vci.service.MetadataService;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectReader;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.JsonNodeType;
import tools.jackson.dataformat.cbor.CBORMapper;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static de.bdr.pidp.issuer.issuance.ConfigTestData.ISSUANCE_CONFIG;
import static de.bdr.pidp.issuer.issuance.ConfigTestData.METADATA_SIGNER_CONFIG;
import static de.bdr.pidp.issuer.issuance.config.IssuanceTestMetadata.ISSUANCE_METADATA;
import static de.bdr.pidp.issuer.testdata.TestUtils.getDisclosures;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CredentialMetadataTest extends IdentityDataBase {

    private static final String EMPTY_KEY_NAME = "...";
    private static final JsonMapper JSON_MAPPER = JsonMapper.builder().build();
    private static final CBORMapper CBOR_MAPPER = new CBORMapper();

    private SdJwtCredentialCreatorV1 sdJwtCredentialCreatorV1;
    private SdJwtCredentialCreatorV2 sdJwtCredentialCreatorV2;
    private SdJwtCredentialCreatorV3Beta sdJwtCredentialCreatorV3Beta;
    private MdocCredentialCreatorV1 mdocCredentialCreatorV1;
    private MdocCredentialCreatorV2 mdocCredentialCreatorV2;
    private MdocCredentialCreatorV3Beta mdocCredentialCreatorV3Beta;

    private JWK holderBindingKey;

    private final PIDIdentityData credentialData = new PIDIdentityDataBuilder().build();
    private final Base64.Decoder urlDecoder = Base64.getUrlDecoder();

    private final Instant now = Instant.now();
    private final CredentialCreator.Validity validity = new CredentialCreator.Validity(now, now.plusSeconds(ISSUANCE_CONFIG.getLifetime().toSeconds()));

    @Spy
    private MetadataSignerConfiguration metadataConfig = METADATA_SIGNER_CONFIG;
    @Spy
    private CredentialIssuerMetadata credentialMetadata = ISSUANCE_METADATA;
    @Spy
    private FileResourceHelper fileResourceHelper;
    @Mock
    private MetadataService metadataService;

    @InjectMocks
    private MetadataController metadataController;

    @BeforeAll
    void setUp() throws UnrecoverableKeyException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        var pidDataBuilderConfig = new PidDataBuilderConfig(ISSUANCE_CONFIG, ISSUANCE_METADATA);
        var signer = new PKCS12CredentialSigner(ISSUANCE_CONFIG);

        sdJwtCredentialCreatorV1 = pidDataBuilderConfig.sdJwtCreatorV1(signer);
        sdJwtCredentialCreatorV2 = pidDataBuilderConfig.sdJwtCreatorV2(signer);
        sdJwtCredentialCreatorV3Beta = pidDataBuilderConfig.sdJwtCreatorV3Beta(signer);
        mdocCredentialCreatorV1 = pidDataBuilderConfig.mdocCreatorV1(signer);
        mdocCredentialCreatorV2 = pidDataBuilderConfig.mdocCreatorV2(signer);
        mdocCredentialCreatorV3Beta = pidDataBuilderConfig.mdocCreatorV3Beta(signer);

        // Prepare parameters
        holderBindingKey = TestUtils.generateEcKey();
    }

    @DisplayName("All sdJwt v1 claims are in metadata")
    @Test
    void test_001a() {
        var statusRef = new StatusReference("http://list-uri", 100);
        String sdJwt = sdJwtCredentialCreatorV1.create(credentialData, holderBindingKey, statusRef, validity);
        String decodedSignature = getSignature(sdJwt);

        List<String> disclosures = getDisclosures(decodedSignature);

        // We search for all end nodes and their frequency.
        HashMap<String, Integer> nodes = disclosures.stream()
            .map(disclosureJson -> new String(urlDecoder.decode(disclosureJson)))
            .map(JSON_MAPPER::readTree).collect(Collectors.toMap(this::getKeyName, this::getCount, Integer::sum, HashMap::new));
        assertThat(nodes).isNotEmpty();

        // the credential configuration id is currently not part of the PID
        compareNodesAndMetadata(nodes, CredentialConfigurationID.SD_JWT_V1.getName());
    }

    @DisplayName("All sdJwt v2 claims are in metadata")
    @Test
    void test_001b() {
        var statusRef = new StatusReference("http://list-uri", 100);
        String sdJwt = sdJwtCredentialCreatorV2.create(credentialData, holderBindingKey, statusRef, validity);
        String decodedSignature = getSignature(sdJwt);

        List<String> disclosures = getDisclosures(decodedSignature);

        // We search for all end nodes and their frequency.
        HashMap<String, Integer> nodes = disclosures.stream()
            .map(disclosureJson -> new String(urlDecoder.decode(disclosureJson)))
            .map(JSON_MAPPER::readTree).collect(Collectors.toMap(this::getKeyName, this::getCount, Integer::sum, HashMap::new));
        assertThat(nodes).isNotEmpty();

        // the credential configuration id is currently not part of the PID
        String configId = CredentialConfigurationID.SD_JWT_V2.getName();
        compareNodesAndMetadata(nodes, configId);
        compareMetadataAndNodes(nodes, configId);
    }

    @DisplayName("All sdJwt v3 claims are in metadata")
    @Test
    void test_001c() {
        var statusRef = new StatusReference("http://list-uri", 100);
        String sdJwt = sdJwtCredentialCreatorV3Beta.create(credentialData, holderBindingKey, statusRef, validity);
        String decodedSignature = getSignature(sdJwt);

        List<String> disclosures = getDisclosures(decodedSignature);

        // We search for all end nodes and their frequency.
        HashMap<String, Integer> nodes = disclosures.stream()
            .map(disclosureJson -> new String(urlDecoder.decode(disclosureJson)))
            .map(JSON_MAPPER::readTree).collect(Collectors.toMap(this::getKeyName, this::getCount, Integer::sum, HashMap::new));
        assertThat(nodes).isNotEmpty();

        // the credential configuration id is currently not part of the PID
        String configId = CredentialConfigurationID.SD_JWT_V3_BETA.getName();
        compareNodesAndMetadata(nodes, configId);
        compareMetadataAndNodes(nodes, configId);
    }

    @DisplayName("All mdoc v1 claims are in metadata")
    @Test
    void test_002a() {
        var statusRef = new StatusReference("http://list-uri", 100);
        String mdoc = mdocCredentialCreatorV1.create(credentialData, holderBindingKey, statusRef, validity);
        Map<List<String>, Object> mdocPidClaimMappings = readPidClaimMappings(mdoc);
        assertThat(mdocPidClaimMappings).isNotEmpty();

        // the credential configuration id is currently not part of the PID
        compareNodesAndMetadata(mdocPidClaimMappings.keySet(), CredentialConfigurationID.MSO_MDOC_V1.getName());
    }

    @DisplayName("All mdoc v2 claims are in metadata")
    @Test
    void test_002b() {
        var statusRef = new StatusReference("http://list-uri", 100);
        String mdoc = mdocCredentialCreatorV2.create(credentialData, holderBindingKey, statusRef, validity);
        Map<List<String>, Object> mdocPidClaimMappings = readPidClaimMappings(mdoc);
        assertThat(mdocPidClaimMappings).isNotEmpty();

        // the credential configuration id is currently not part of the PID
        String configId = CredentialConfigurationID.MSO_MDOC_V2.getName();
        compareMetadataAndNodes(mdocPidClaimMappings.keySet(), configId);
        compareNodesAndMetadata(mdocPidClaimMappings.keySet(), configId);
    }

    @DisplayName("All mdoc v3 claims are in metadata")
    @Test
    void test_002c() {
        var statusRef = new StatusReference("http://list-uri", 100);
        String mdoc = mdocCredentialCreatorV3Beta.create(credentialData, holderBindingKey, statusRef, validity);
        Map<List<String>, Object> mdocPidClaimMappings = readPidClaimMappings(mdoc);
        assertThat(mdocPidClaimMappings).isNotEmpty();

        // the credential configuration id is currently not part of the PID
        String configId = CredentialConfigurationID.MSO_MDOC_V3_BETA.getName();
        compareMetadataAndNodes(mdocPidClaimMappings.keySet(), configId);
        compareNodesAndMetadata(mdocPidClaimMappings.keySet(), configId);
    }

    /**
     * Checks if all claim_identifier (last element of claim_path) and count (for nested objects with same claim_identifier) are present in metadata
     */
    private void compareNodesAndMetadata(HashMap<String, Integer> nodes, String credentialConfiguration) {
        Set<List<String>> claimsPaths = getMetadataClaimPaths(credentialConfiguration);
        HashMap<String, Integer> claims = claimsPaths.stream().map(List::getLast).collect(Collectors.toMap(v -> v, _ -> 1, Integer::sum, HashMap::new));
        assertThat(claims).isNotEmpty();

        nodes.forEach((k,v) -> {
            if (v > 0) {
                assertThat(claims).containsKey(k);
                assertThat(claims.get(k)).isGreaterThanOrEqualTo(v);
            }
        });
    }

    /**
     * Checks if all metadata properties are present in claim_identifier (last element of claim_path) and count (for nested objects with same claim_identifier)
     */
    private void compareMetadataAndNodes(HashMap<String, Integer> nodes, String credentialConfiguration) {
        Set<List<String>> claimsPaths = getMetadataClaimPaths(credentialConfiguration);
        HashMap<String, Integer> claims = claimsPaths.stream().map(List::getLast).collect(Collectors.toMap(v -> v, _ -> 1, Integer::sum, HashMap::new));
        assertThat(claims).isNotEmpty();

        // Reduce the count of parent paths, since parent paths are never present in the credential on their own.
        claimsPaths.forEach(path -> {
            if (path.size() > 1) {
                claims.computeIfPresent(path.getFirst(), (_, _) -> 0);
            }
        });

        claims.forEach((k,v) -> {
            if (v > 0) {
                assertThat(nodes).containsEntry(k, v);
            }
        });
    }

    /**
     * Checks if all claim_paths are present in metadata
     */
    private void compareNodesAndMetadata(Set<List<String>> claimPaths, String credentialConfiguration) {
        Set<List<String>> claims = getMetadataClaimPaths(credentialConfiguration);
        assertThat(claims).isNotEmpty();

        claimPaths.forEach(p -> assertThat(claims).contains(p));
    }

    /**
     * Checks if all metadata properties are present in claim_paths
     */
    private void compareMetadataAndNodes(Set<List<String>> claimPaths, String credentialConfiguration) {
        Set<List<String>> claims = getMetadataClaimPaths(credentialConfiguration);
        assertThat(claims).isNotEmpty();
        claims.forEach(p -> assertThat(claimPaths).contains(p));
    }

    /**
     * @return claim_paths as Set<[namespace?, nested_path?, claim_identifier]>
     */
    private Set<List<String>> getMetadataClaimPaths(String credentialConfiguration) {
        ResponseEntity<String> metadataResponse = metadataController.getCredentialIssuerMetadataJSON();
        JsonNode metadata = JSON_MAPPER.readTree(metadataResponse.getBody());
        JsonNode claimsMetadataJson = metadata.get("credential_configurations_supported").get(credentialConfiguration)
            .get("credential_metadata").get("claims");
        return claimsMetadataJson.findValues("path").stream().filter(JsonNode::isArray).map(JsonNode::values)
            .map(c -> c.stream().map(JsonNode::asString).toList())
            .collect(Collectors.toSet());
    }

    /**
     * @return claim_mappings as Map<[namespace, nested_path?, claim_identifier] -> claim_value>
     */
    @NotNull
    private Map<List<String>, Object> readPidClaimMappings(String mdoc) {
        byte[] decodedMdoc = urlDecoder.decode(mdoc);
        JsonNode jsonNode = CBOR_MAPPER.readTree(decodedMdoc).findValue("nameSpaces");
        ObjectReader reader = CBOR_MAPPER.readerFor(new TypeReference<Map<String, List<byte[]>>>() {});
        Map<String, List<byte[]>> list = reader.readValue(jsonNode);
        return list.entrySet().stream()
            .flatMap(namespace -> namespace.getValue().stream()
                .map(cbor -> CBOR_MAPPER.readValue(cbor, DecodedMdocPidValue.class))
                .flatMap(pidValue -> switch (pidValue.elementValue()) {
                    case Map<?, ?> nested -> nested.entrySet().stream()
                        .map(e -> Map.entry(List.of(namespace.getKey(), pidValue.elementIdentifier(), (String) e.getKey()), e.getValue()));
                    default -> Stream.of(Map.entry(
                        List.of(namespace.getKey(), pidValue.elementIdentifier()),
                        pidValue.elementValue()));
                }))
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private record DecodedMdocPidValue(String random, int digestID, String elementIdentifier, Object elementValue) {
    }

    private static String getSignature(String sdJwt) {
        String[] split = sdJwt.split("\\.");
        return split[2];
    }

    private String getKeyName(JsonNode node) {
        if (node.size() > 2) {
            return node.get(1).asString();
        } else {
            return EMPTY_KEY_NAME;
        }
    }

    private Integer getCount(JsonNode node) {
        if (node.size() <= 2 || (node.get(2).getNodeType() == JsonNodeType.OBJECT)) {
            return 0;
        } else {
            return 1;
        }
    }
}
