/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.JSONObjectUtils;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.issuance.config.IssuanceTestMetadata;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfiguration;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.core.StatusReference;
import de.bdr.pidp.issuer.issuance.core.signer.PKCS12CredentialSigner;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.JsonNode;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static de.bdr.pidp.issuer.issuance.ConfigTestData.ISSUANCE_CONFIG;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.fail;

class SdJwtCredentialCreatorV3BetaTest extends SdJwtCredentialCreatorTestBase {
    private static final Instant TODAY = OffsetDateTime.now(ZoneId.of("Europe/Berlin")).truncatedTo(ChronoUnit.DAYS).toInstant();
    private static final Duration LIFETIME = ISSUANCE_CONFIG.getLifetime();
    private static final int NR_BIRTH_PLACE_PROPERTIES = 1;

    private static SdJwtCredentialCreatorV3Beta subject;

    private final JWK bindingKey = TestUtils.generateEcKey();

    private static ECDSAVerifier ecdsaVerifier;
    private static String issuer;
    private static String vct;
    private static String format;
    private int statusIndex = 1;

    @BeforeAll
    static void setUp() throws JOSEException, IOException, UnrecoverableKeyException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        var sdJwtMetadata = (CredentialConfiguration.SdJwt) IssuanceTestMetadata.ISSUANCE_METADATA.credentialConfigurationsSupported().get(CredentialConfigurationID.SD_JWT_V3_BETA);
        issuer = IssuanceTestMetadata.ISSUANCE_METADATA.credentialIssuer().getValue();
        vct = sdJwtMetadata.vct();
        format = sdJwtMetadata.format();

        // Create sdJwtBuilder
        var pkcs12Signer = new PKCS12CredentialSigner(ISSUANCE_CONFIG);
        subject = new SdJwtCredentialCreatorV3Beta(issuer, pkcs12Signer, vct, format);

        // Create verifier
        var sigKey = ECKey.parse(pkcs12Signer.getCertificateChain().getFirst());
        ecdsaVerifier = new ECDSAVerifier(sigKey);
    }

    @DisplayName("Verify SD-JWT signature and it contains the correct plain properties iss, _sd_alg, vct and status")
    @Test
    void test001() {
        // Given
        var statusRef = getStatusReference();
        var data = new PIDIdentityDataBuilder().build();

        // When
        String sdJwt = subject.create(data, bindingKey, statusRef, validity);

        // Then
        var decodedPayload = getDecodedPayload(sdJwt);
        var payloadNode = JSON_MAPPER.readTree(decodedPayload);

        verifySignature(sdJwt, ecdsaVerifier);
        assertThat(payloadNode.get("vct").asString()).isEqualTo(vct);
        assertThat(payloadNode.get("iss").asString()).isEqualTo(issuer);
        assertThat(payloadNode.get("_sd_alg").asString()).isEqualTo("sha-256");
        assertThat(payloadNode.get("status").get("status_list").get("uri").asString()).isEqualTo(statusRef.uri());
        assertThat(payloadNode.get("status").get("status_list").get("idx").asInt()).isEqualTo(statusRef.index());
    }

    @DisplayName("Verify SD-JWT contains the correct nbf and exp")
    @Test
    void test002() {
        // Given
        var statusRef = getStatusReference();
        var data = new PIDIdentityDataBuilder().build();

        // When
        String sdJwt = subject.create(data, bindingKey, statusRef, validity);

        // Then
        var decodedPayload = getDecodedPayload(sdJwt);
        var payloadNode = JSON_MAPPER.readTree(decodedPayload);

        assertThat(payloadNode.get("nbf").asLong()).extracting(Instant::ofEpochSecond).isEqualTo(TODAY);
        assertThat(payloadNode.get("exp").asLong()).extracting(Instant::ofEpochSecond).isEqualTo(TODAY.plus(LIFETIME));
    }

    @DisplayName("Verify SD-JWT contains binding key as confirmation")
    @Test
    void test003() throws ParseException {
        // Given
        var statusRef = getStatusReference();
        var data = new PIDIdentityDataBuilder().build();

        // When
        String sdJwt = subject.create(data, bindingKey, statusRef, validity);

        // Then
        var decodedPayload = getDecodedPayload(sdJwt);
        var payloadNode = JSON_MAPPER.readTree(decodedPayload);
        var jwkNode = payloadNode.get("cnf").get("jwk");
        var jwk = JWK.parse(jwkNode.toString());
        assertThat(jwk).isEqualTo(bindingKey);
    }

    @DisplayName("Verify SD-JWT contains a disclosure for all sd properties")
    @Test
    void test004() throws NoSuchAlgorithmException {
        // Given
        var statusRef = getStatusReference();
        var data = new PIDIdentityDataBuilder().build();

        // When
        String sdJwt = subject.create(data, bindingKey, statusRef, validity);

        // Then
        String decodedPayload = getDecodedPayload(sdJwt);
        String decodedSignature = getSignature(sdJwt);

        List<String> disclosures = getDisclosures(decodedSignature);
        List<String> listSdHashes = getAllSdHashValues(decodedPayload);
        List<String> hashedDisclosures = toHashedDisclosures(disclosures, MessageDigest.getInstance("SHA-256"));

        verifySignature(sdJwt, ecdsaVerifier);
        assertThat(listSdHashes)
            .containsAnyElementsOf(hashedDisclosures)
            .hasSize(disclosures.size() - NR_DECOY_DIGESTS - NR_NESTED_SD_AGE_SELECTOR
                - NR_MAX_ADDRESS_PROPERTIES - NR_BIRTH_PLACE_PROPERTIES);
    }

    @DisplayName("Verify SD-JWT all claims were disclosed")
    @Test
    @SuppressWarnings("java:S5961")
    void test005() throws NoSuchAlgorithmException {
        // Given
        var statusRef = getStatusReference();
        var data = new PIDIdentityDataBuilder().build();

        // When
        String sdJwt = subject.create(data, bindingKey, statusRef, validity);

        // Then
        String decodedSignature = getSignature(sdJwt);

        List<String> disclosures = getDisclosures(decodedSignature);
        List<String> hashedDisclosures = toHashedDisclosures(disclosures, MessageDigest.getInstance("SHA-256"));

        Map<String, JsonNode> parsedDisclosuresMap = parseDisclosures(disclosures);

        Assertions.assertAll(
            () -> assertThat(parsedDisclosuresMap.get("issuing_country").asString()).isEqualTo("DE"),
            () -> assertThat(parsedDisclosuresMap.get("issuing_authority").asString()).isEqualTo("DE"),
            () -> assertThat(parsedDisclosuresMap.get("source_document_type").asString()).isEqualTo("ID"),
            () -> assertThat(parsedDisclosuresMap.get("family_name").asString()).isEqualTo("MUSTERMANN"),
            () -> assertThat(parsedDisclosuresMap.get("given_name").asString()).isEqualTo("ERIKA"),
            () -> assertThat(parsedDisclosuresMap.get("birth_name").asString()).isEqualTo("GABLER"),
            () -> assertThat(parsedDisclosuresMap.get("birthdate").asString()).isEqualTo("1964-08-12"),
            () -> assertThat(parsedDisclosuresMap.get("raw_eid_birth_date").asString()).isEqualTo("1964-08-12"),
            () -> assertThat(parsedDisclosuresMap.get("nationalities").size()).isEqualTo(2),
            () -> assertThat(parsedDisclosuresMap.get(EMPTY_KEY_NAME).asString()).isEqualTo("DE"),
            () -> assertThat(parsedDisclosuresMap.get("age_equal_or_over").get("_sd")).hasSize(NR_NESTED_SD_AGE_SELECTOR),
            () -> assertThat(parsedDisclosuresMap.get("12").asBoolean()).isTrue(),
            () -> assertThat(parsedDisclosuresMap.get("14").asBoolean()).isTrue(),
            () -> assertThat(parsedDisclosuresMap.get("16").asBoolean()).isTrue(),
            () -> assertThat(parsedDisclosuresMap.get("18").asBoolean()).isTrue(),
            () -> assertThat(parsedDisclosuresMap.get("21").asBoolean()).isTrue(),
            () -> assertThat(parsedDisclosuresMap.get("65").asBoolean()).isFalse(),
            () -> assertThat(parsedDisclosuresMap.get("no_place_info")).isNull(),
            () -> assertThat(parsedDisclosuresMap.get("address")).hasSize(1),
            () -> assertThat(parsedDisclosuresMap.get("address").get("_sd")).hasSize(5),
            () -> assertThat(parsedDisclosuresMap.get("locality")).hasSize(2),
            () -> assertThat(parsedDisclosuresMap.get("locality").get(0).asString()).isEqualTo("BERLIN"),
            () -> assertThat(parsedDisclosuresMap.get("locality").get(1).asString()).isEqualTo("KÖLN"),
            () -> assertThat(parsedDisclosuresMap.get("country").asString()).isEqualTo("DE"),
            () -> assertThat(parsedDisclosuresMap.get("region").asString()).isEqualTo("NRW"),
            () -> assertThat(parsedDisclosuresMap.get("postal_code").asString()).isEqualTo("51147"),
            () -> assertThat(parsedDisclosuresMap.get("street_address").asString()).isEqualTo("HEIDESTRASSE 17"),
            () -> assertThat(parsedDisclosuresMap.get("also_known_as").asString()).isEqualTo("MUSTERFRAU"),
            () -> assertThat(parsedDisclosuresMap.get("title").asString()).isEqualTo("DR")
        );

        List<String> addressSdHashes = getAllSdHashes(parsedDisclosuresMap.get("address"));
        assertThat(addressSdHashes)
            .containsAnyElementsOf(hashedDisclosures)
            .hasSize(NR_MAX_ADDRESS_PROPERTIES);

        List<String> birthplaceSdHashes = getAllSdHashes(parsedDisclosuresMap.get("place_of_birth"));
        assertThat(birthplaceSdHashes)
            .containsAnyElementsOf(hashedDisclosures)
            .hasSize(NR_BIRTH_PLACE_PROPERTIES);

        List<String> ageSdHashes = getAllSdHashes(parsedDisclosuresMap.get("age_equal_or_over"));
        assertThat(ageSdHashes)
            .containsAnyElementsOf(hashedDisclosures)
            .hasSize(NR_NESTED_SD_AGE_SELECTOR);
    }

    @DisplayName("Verify SD-JWT all claims were disclosed with minimal data")
    @Test
    @SuppressWarnings("java:S5961")
    void test006() throws NoSuchAlgorithmException {
        // Given
        var statusRef = getStatusReference();
        var data = new PIDIdentityDataBuilder()
            .givenNames(null)
            .familyNames(null)
            .artisticName(null)
            .academicTitle(null)
            .birthName(null)
            .placeOfBirth(PIDIdentityDataBuilder.PlaceOfBirthBuilder.noPlaceInfo())
            .placeOfResidence(PIDIdentityDataBuilder.PlaceBuilder.noPlaceInfo())
            .build();

        // When
        String sdJwt = subject.create(data, bindingKey, statusRef, validity);

        // Then
        String decodedSignature = getSignature(sdJwt);

        List<String> disclosures = getDisclosures(decodedSignature);
        List<String> hashedDisclosures = toHashedDisclosures(disclosures, MessageDigest.getInstance("SHA-256"));

        Map<String, JsonNode> parsedDisclosuresMap = parseDisclosures(disclosures);

        Assertions.assertAll(
            () -> assertThat(parsedDisclosuresMap).hasSize(26),
            () -> assertThat(parsedDisclosuresMap.get("issuing_country").asString()).isEqualTo("DE"),
            () -> assertThat(parsedDisclosuresMap.get("issuing_authority").asString()).isEqualTo("DE"),
            () -> assertThat(parsedDisclosuresMap.get("source_document_type").asString()).isEqualTo("ID"),
            () -> assertThat(parsedDisclosuresMap.get("family_name").asString()).isEmpty(),
            () -> assertThat(parsedDisclosuresMap.get("given_name").asString()).isEmpty(),
            () -> assertThat(parsedDisclosuresMap.get("birth_name").asString()).isEmpty(),
            () -> assertThat(parsedDisclosuresMap.get("birthdate").asString()).isEqualTo("1964-08-12"),
            () -> assertThat(parsedDisclosuresMap.get("raw_eid_birth_date").asString()).isEqualTo("1964-08-12"),
            () -> assertThat(parsedDisclosuresMap.get("nationalities").size()).isEqualTo(2),
            () -> assertThat(parsedDisclosuresMap.get(EMPTY_KEY_NAME).asString()).isEqualTo("DE"),
            () -> assertThat(parsedDisclosuresMap.get("age_equal_or_over").get("_sd")).hasSize(NR_NESTED_SD_AGE_SELECTOR),
            () -> assertThat(parsedDisclosuresMap.get("address")).hasSize(1),
            () -> assertThat(parsedDisclosuresMap.get("address").get("_sd")).hasSize(5),
            () -> assertThat(parsedDisclosuresMap.get("locality")).hasSize(2),
            () -> assertThat(parsedDisclosuresMap.get("locality").get(0).asString()).isEmpty(),
            () -> assertThat(parsedDisclosuresMap.get("locality").get(1).asString()).isEmpty(),
            () -> assertThat(parsedDisclosuresMap.get("country").asString()).isEmpty(),
            () -> assertThat(parsedDisclosuresMap.get("region").asString()).isEmpty(),
            () -> assertThat(parsedDisclosuresMap.get("postal_code").asString()).isEmpty(),
            () -> assertThat(parsedDisclosuresMap.get("street_address").asString()).isEmpty(),
            () -> assertThat(parsedDisclosuresMap.get("12").asBoolean()).isTrue(),
            () -> assertThat(parsedDisclosuresMap.get("14").asBoolean()).isTrue(),
            () -> assertThat(parsedDisclosuresMap.get("16").asBoolean()).isTrue(),
            () -> assertThat(parsedDisclosuresMap.get("18").asBoolean()).isTrue(),
            () -> assertThat(parsedDisclosuresMap.get("21").asBoolean()).isTrue(),
            () -> assertThat(parsedDisclosuresMap.get("65").asBoolean()).isFalse(),
            () -> assertThat(parsedDisclosuresMap.get("no_place_info")).isNull(),
            () -> assertThat(parsedDisclosuresMap.get("also_known_as").asString()).isEmpty(),
            () -> assertThat(parsedDisclosuresMap.get("title").asString()).isEmpty(),
            () -> assertThat(parsedDisclosuresMap.get("date_of_expiry")).isNull()
        );

        List<String> ageSdHashes = getAllSdHashes(parsedDisclosuresMap.get("age_equal_or_over"));
        assertThat(ageSdHashes)
            .containsAnyElementsOf(hashedDisclosures)
            .hasSize(NR_NESTED_SD_AGE_SELECTOR);
    }

    @DisplayName("Verify 3 letter ICAO country code was supported for nationality")
    @Test
    void test007() {
        // Given
        var statusRef = getStatusReference();
        var data = new PIDIdentityDataBuilder()
            .nationality("AZE")
            .build();

        // When, Then
        assertThatNoException().isThrownBy(() -> subject.create(data, bindingKey, statusRef, validity));
    }

    @DisplayName("Verify iso-3166-1 country codes for nationality are not supported")
    @ParameterizedTest
    @ValueSource(strings = {"_", "!-", "123", "ABCD", "AAA", "AA", "Z", "GBD", "GBN", "GBO", "GBS", "GBP", "KS", "RKS", "EU", "EUE"})
    void test008(String invalidCountryCode) {
        // Given
        var statusRef = getStatusReference();
        var data = new PIDIdentityDataBuilder()
            .nationality(invalidCountryCode)
            .build();

        // When, Then
        assertThatExceptionOfType(PidServerException.class).isThrownBy(() -> subject.create(data, bindingKey, statusRef, validity));
    }

    @DisplayName("Verify SD-JWT header contains unprotected key chain")
    @Test
    void test009() throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, ParseException {
        // Given
        var statusRef = getStatusReference();
        var data = new PIDIdentityDataBuilder().build();

        // When
        String sdJwt = subject.create(data, bindingKey, statusRef, validity);

        // Then
        String decodedHeader = getDecodedHeader(sdJwt);
        var decodedHeaderMap = JSONObjectUtils.parse(decodedHeader);

        assertThat(decodedHeaderMap).isNotEmpty()
            .hasFieldOrPropertyWithValue("alg", "ES256")
            .hasFieldOrPropertyWithValue("typ", format)
            .hasFieldOrProperty("kid").hasFieldOrProperty("x5c")
            .hasSize(4);

        if (!(decodedHeaderMap.get("x5c") instanceof List<?> certChain)) {
            fail("x5c header not a list");
            return;
        }

        var signerCertificateChain = givenSignerCertificateChain();
        assertThat(certChain).hasSizeLessThanOrEqualTo(signerCertificateChain.length).hasSize(1);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode((String) certChain.getFirst())));
        assertThat(certificate).isEqualTo(signerCertificateChain[0]);
    }

    private StatusReference getStatusReference() {
        return new StatusReference("http://list-uri", statusIndex++);
    }
}
