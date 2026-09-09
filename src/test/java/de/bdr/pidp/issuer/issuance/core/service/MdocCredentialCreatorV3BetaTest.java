/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.service;

import COSE.CoseException;
import COSE.OneKey;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.upokecenter.cbor.CBORObject;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfiguration;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.core.StatusReference;
import de.bdr.pidp.issuer.issuance.core.signer.PKCS12CredentialSigner;
import de.bdr.pidp.issuer.testdata.TestUtils;
import de.bundesdruckerei.mdoc.kotlin.core.auth.IssuerAuth;
import de.bundesdruckerei.mdoc.kotlin.core.auth.IssuerSignedItem;
import de.bundesdruckerei.mdoc.kotlin.core.auth.MobileSecurityObject;
import de.bundesdruckerei.mdoc.kotlin.core.auth.ValidityInfo;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static de.bdr.pidp.issuer.issuance.ConfigTestData.ISSUANCE_CONFIG;
import static de.bdr.pidp.issuer.issuance.config.IssuanceTestMetadata.ISSUANCE_METADATA;
import static de.bdr.pidp.issuer.issuance.core.service.MdocCredentialCreatorTestBase.CoseKeyCommonParameters.KTY;
import static de.bdr.pidp.issuer.issuance.core.service.MdocCredentialCreatorTestBase.CoseKeyCommonParameters.X;
import static de.bdr.pidp.issuer.issuance.core.service.MdocCredentialCreatorTestBase.CoseKeyCommonParameters.Y;
import static de.bdr.pidp.issuer.issuance.core.service.MdocCredentialCreatorTestBase.CoseKeyTypes.EC2;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.InstanceOfAssertFactories.BOOLEAN;
import static org.assertj.core.api.InstanceOfAssertFactories.list;
import static org.assertj.core.api.InstanceOfAssertFactories.map;
import static org.assertj.core.api.SoftAssertions.assertSoftly;

class MdocCredentialCreatorV3BetaTest extends MdocCredentialCreatorTestBase {

    private static final Instant TODAY = OffsetDateTime.now(ZoneId.of("Europe/Berlin")).truncatedTo(ChronoUnit.DAYS).toInstant();
    private static final Duration LIFETIME = ISSUANCE_CONFIG.getLifetime();

    private static MdocCredentialCreatorV3Beta subject;
    private static Certificate[] signerCertificateChain;

    private final JWK bindingKey = TestUtils.generateEcKey();

    private int statusIndex = 1;

    @BeforeAll
    static void setUp() throws UnrecoverableKeyException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        var mdocMetadata = (CredentialConfiguration.Mdoc) ISSUANCE_METADATA.credentialConfigurationsSupported().get(CredentialConfigurationID.MSO_MDOC_V3_BETA);
        var signer = new PKCS12CredentialSigner(ISSUANCE_CONFIG);
        subject = new MdocCredentialCreatorV3Beta(signer, mdocMetadata.doctype());

        signerCertificateChain = givenSignerCertificateChain();
    }

    @DisplayName("Verify mdoc is ISSUER_SIGNED and the JSON contained issuerAuth and nameSpaces at the top level")
    @Test
    void test001() {
        // Given
        var statusRef = getStatusReference();
        var data = new PIDIdentityDataBuilder().build();

        // When
        var mdoc = subject.create(data, bindingKey, statusRef, validity);

        // Then
        var mdocNode = readMdocNode(mdoc);

        assertThat(mdocNode).hasSize(2);
        assertThat(mdocNode.get("issuerAuth")).isNotNull();
        assertThat(mdocNode.get("nameSpaces")).isNotNull();
    }

    @DisplayName("IssuerAuth")
    @Nested
    class MdocIssuerAuthTest {

        @DisplayName("Verify mdoc contained correct validity info")
        @Test
        void test001() {
            // Given
            var statusRef = getStatusReference();
            var data = new PIDIdentityDataBuilder().build();

            // When
            var mdoc = subject.create(data, bindingKey, statusRef, validity);

            // Then
            var mdocNode = readMdocNode(mdoc);
            var authNode = readIssuerAuthNode(mdocNode);
            var msoBinaryNode = readMSOBinaryNode(authNode);

            var mso = MobileSecurityObject.Companion.fromTaggedCBOR(decodeFromBytes(msoBinaryNode));

            ValidityInfo validityInfo = mso.getValidityInfo();
            var signed = validityInfo.getSigned().toInstant();
            var validFrom = validityInfo.getValidFrom().toInstant();
            var validUntil = validityInfo.getValidUntil().toInstant();
            assertThat(signed).isEqualTo(TODAY);
            assertThat(validFrom).isEqualTo(TODAY);
            assertThat(validUntil).isEqualTo(TODAY.plus(LIFETIME));
        }

        @DisplayName("Verify validity info used 'tdate' type for date/time attributes")
        @Test
        void test002() {
            // Given
            var statusRef = getStatusReference();
            var data = new PIDIdentityDataBuilder().build();

            // When
            var mdoc = subject.create(data, bindingKey, statusRef, validity);

            // Then
            var mdocNode = readMdocNode(mdoc);
            var authNode = readIssuerAuthNode(mdocNode);
            var msoNode = readMSOBinaryNode(authNode);
            CBORObject mso = readMSO(msoNode);
            CBORObject validityInfo = mso.get("validityInfo");
            CBORObject signed = validityInfo.get("signed");
            CBORObject validFrom = validityInfo.get("validFrom");
            CBORObject validUntil = validityInfo.get("validUntil");

            assertThat(signed).satisfies(
                MdocCredentialCreatorTestBase::assertTypeIsStandardDateTimeString
            );
            assertThat(validFrom).satisfies(
                MdocCredentialCreatorTestBase::assertTypeIsStandardDateTimeString
            );
            assertThat(validUntil).satisfies(
                MdocCredentialCreatorTestBase::assertTypeIsStandardDateTimeString
            );
        }

        @DisplayName("Verify mdoc contained correct status info")
        @Test
        void test003() {
            // Given
            var statusRef = getStatusReference();
            var data = new PIDIdentityDataBuilder().build();

            // When
            var mdoc = subject.create(data, bindingKey, statusRef, validity);

            // Then
            var mdocNode = readMdocNode(mdoc);
            var authNode = readIssuerAuthNode(mdocNode);
            var msoNode = readMSOBinaryNode(authNode);
            var mso = readMSO(msoNode);

            var statusList = mso.get("status").get("status_list");
            assertThat(statusList.get("idx").AsInt32()).isEqualTo(statusRef.index());
            assertThat(statusList.get("uri").AsString()).isEqualTo(statusRef.uri());
        }


        @DisplayName("Verify mdoc IssuerAuth has correct signature")
        @Test
        void test004() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, CoseException {
            // Given
            var statusRef = getStatusReference();
            var data = new PIDIdentityDataBuilder().build();

            // When
            var mdoc = subject.create(data, bindingKey, statusRef, validity);

            // Then
            var decodedMdoc = CBORObject.DecodeFromBytes(getDecodedString(mdoc));
            var issuerAuth = IssuerAuth.Companion.fromCBOR(decodedMdoc.get("issuerAuth"));
            var pubKey = new OneKey(getSignerPub(), null);
            assertThat(issuerAuth.validate(pubKey)).isTrue();
        }

        @DisplayName("Verify mdoc issuerAuth (MSO) COSE_Sign1 was signed with ECDSA w/ SHA-256")
        @Test
        void test005() {
            // Given
            var statusRef = getStatusReference();
            var data = new PIDIdentityDataBuilder().build();

            // When
            var mdoc = subject.create(data, bindingKey, statusRef, validity);

            // Then
            var mdocNode = readMdocNode(mdoc);
            var authNode = readIssuerAuthNode(mdocNode);

            var protectedHeaderNode = CBOR_MAPPER.readTree(authNode.get(0).binaryValue());
            assertThat(protectedHeaderNode.get(String.valueOf(CoseHeaderParameters.ALG.label)).asInt()).isEqualTo(CoseAlgorithms.ECDSA.value);
        }

        @DisplayName("Verify mdoc issuerAuth (MSO) COSE_Sign1 contained key chain in unprotected header")
        @Test
        void test006() throws CertificateException {
            // Given
            var statusRef = getStatusReference();
            var data = new PIDIdentityDataBuilder().build();

            // When
            var mdoc = subject.create(data, bindingKey, statusRef, validity);

            // Then
            var mdocNode = readMdocNode(mdoc);
            var authNode = readIssuerAuthNode(mdocNode);

            var unprotectedHeaderNode = authNode.get(1);
            List<? extends Certificate> certificateChain = getCertificateChain(unprotectedHeaderNode);

            assertThat(certificateChain.size()).isLessThanOrEqualTo(signerCertificateChain.length).isEqualTo(1);
            assertThat(certificateChain.getFirst()).isEqualTo(signerCertificateChain[0]);
        }

        @DisplayName("Verify mdoc issuerAuth (MSO) was structured according to ISO/IEC 18013-5")
        @Test
        void test007() throws JOSEException {
            // Given
            var statusRef = getStatusReference();
            var data = new PIDIdentityDataBuilder().build();
            var publicKey = bindingKey.toECKey().toECPublicKey();
            BigInteger deviceBindingKeyX = publicKey.getW().getAffineX();
            BigInteger deviceBindingKeyY = publicKey.getW().getAffineY();

            // When
            var mdoc = subject.create(data, bindingKey, statusRef, validity);

            // Then
            var mdocNode = readMdocNode(mdoc);
            var authNode = readIssuerAuthNode(mdocNode);
            var msoBinaryNode = readMSOBinaryNode(authNode);
            var msoNode = readMSONode(msoBinaryNode);

            assertThat(msoNode.get("version").asString()).isEqualTo("1.0");
            assertThat(msoNode.get("digestAlgorithm").asString()).isEqualTo("SHA-256");
            assertThat(msoNode.get("docType").asString()).isEqualTo(DOC_TYPE);

            JsonNode deviceKey = msoNode.get("deviceKeyInfo").get("deviceKey");
            assertThat(deviceKey.get(KTY.labelStr()).asInt()).isEqualTo(EC2.value);

            BigInteger msoDeviceKeyX = new BigInteger(1, deviceKey.get(X.labelStr()).binaryValue());
            assertThat(msoDeviceKeyX).isEqualTo(deviceBindingKeyX);

            BigInteger msoDeviceKeyY = new BigInteger(1, deviceKey.get(Y.labelStr()).binaryValue());
            assertThat(msoDeviceKeyY).isEqualTo(deviceBindingKeyY);
        }
    }

    @DisplayName("Namespaces")
    @Nested
    class MdocNamespacesTest {

        @DisplayName("Verify mdoc V3 beta contained all eu claims")
        @Test
        void test001() {
            // Given
            var statusRef = getStatusReference();
            var data = new PIDIdentityDataBuilder().build();

            // When
            var mdoc = subject.create(data, bindingKey, statusRef, validity);

            // Then
            Map<String, Object> pidValues = readPidValues(mdoc, EU_NAMESPACE);

            assertSoftly(soft -> {
                soft.assertThat(pidValues).extractingByKey("expiry_date").isNull();
                soft.assertThat(pidValues).hasSize(12);
                soft.assertThat(pidValues).extractingByKey("family_name").isEqualTo("MUSTERMANN");
                soft.assertThat(pidValues).extractingByKey("given_name").isEqualTo("ERIKA");
                soft.assertThat(pidValues).extractingByKey("birth_date").isEqualTo("1964-08-12");
                soft.assertThat(pidValues).extractingByKey("nationality").asInstanceOf(list(String.class)).containsExactly("DE");
                soft.assertThat(pidValues).extractingByKey("place_of_birth").asInstanceOf(map(String.class, String.class))
                    .hasSize(1).containsEntry("locality", "BERLIN");
                soft.assertThat(pidValues).extractingByKey("resident_country").isEqualTo("DE");
                soft.assertThat(pidValues).extractingByKey("resident_state").isEqualTo("NRW");
                soft.assertThat(pidValues).extractingByKey("resident_city").isEqualTo("KÖLN");
                soft.assertThat(pidValues).extractingByKey("resident_postal_code").isEqualTo("51147");
                soft.assertThat(pidValues).extractingByKey("resident_street").isEqualTo("HEIDESTRASSE 17");
                soft.assertThat(pidValues).extractingByKey("issuing_authority").isEqualTo("DE");
                soft.assertThat(pidValues).extractingByKey("issuing_country").isEqualTo("DE");
            });
        }

        @DisplayName("Verify mdoc V3 beta contained all de claims")
        @Test
        void test002() {
            // Given
            var statusRef = getStatusReference();
            var data = new PIDIdentityDataBuilder().build();

            // When
            var mdoc = subject.create(data, bindingKey, statusRef, validity);

            // Then
            Map<String, Object> pidValues = readPidValues(mdoc, DE_NAMESPACE);

            assertSoftly(soft -> {
                soft.assertThat(pidValues).hasSize(11);
                soft.assertThat(pidValues).extractingByKey("age_over_12").asInstanceOf(BOOLEAN).isTrue();
                soft.assertThat(pidValues).extractingByKey("age_over_14").asInstanceOf(BOOLEAN).isTrue();
                soft.assertThat(pidValues).extractingByKey("age_over_16").asInstanceOf(BOOLEAN).isTrue();
                soft.assertThat(pidValues).extractingByKey("age_over_18").asInstanceOf(BOOLEAN).isTrue();
                soft.assertThat(pidValues).extractingByKey("age_over_21").asInstanceOf(BOOLEAN).isTrue();
                soft.assertThat(pidValues).extractingByKey("age_over_65").asInstanceOf(BOOLEAN).isFalse();
                soft.assertThat(pidValues).extractingByKey("birth_name").isEqualTo("GABLER");
                soft.assertThat(pidValues).extractingByKey("source_document_type").isEqualTo("ID");
                soft.assertThat(pidValues).doesNotContainKey("place_of_birth");
                soft.assertThat(pidValues).extractingByKey("also_known_as").isEqualTo("MUSTERFRAU");
                soft.assertThat(pidValues).extractingByKey("academic_title").isEqualTo("DR");
                soft.assertThat(pidValues).extractingByKey("raw_eid_birth_date").isEqualTo("1964-08-12");
            });
        }

        @DisplayName("Verify mdoc V3 beta built eu pid namespace correct with minimal data")
        @Test
        void test003() {
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
            var mdoc = subject.create(data, bindingKey, statusRef, validity);

            // Then
            Map<String, Object> pidValues = readPidValues(mdoc, EU_NAMESPACE);
            assertSoftly(soft -> {
                soft.assertThat(pidValues).hasSize(12);
                soft.assertThat(pidValues).extractingByKey("family_name").isEqualTo("");
                soft.assertThat(pidValues).extractingByKey("given_name").isEqualTo("");
                soft.assertThat(pidValues).extractingByKey("birth_date").isEqualTo("1964-08-12");
                soft.assertThat(pidValues).extractingByKey("nationality").asInstanceOf(list(String.class)).containsExactly("DE");
                soft.assertThat(pidValues).extractingByKey("place_of_birth").asInstanceOf(map(String.class, String.class))
                    .hasSize(1).containsEntry("locality", "");
                soft.assertThat(pidValues).extractingByKey("resident_country").isEqualTo("");
                soft.assertThat(pidValues).extractingByKey("resident_state").isEqualTo("");
                soft.assertThat(pidValues).extractingByKey("resident_city").isEqualTo("");
                soft.assertThat(pidValues).extractingByKey("resident_postal_code").isEqualTo("");
                soft.assertThat(pidValues).extractingByKey("resident_street").isEqualTo("");
                soft.assertThat(pidValues).extractingByKey("issuing_authority").isEqualTo("DE");
                soft.assertThat(pidValues).extractingByKey("issuing_country").isEqualTo("DE");
                soft.assertThat(pidValues).doesNotContainKey("expiry_date");
            });
        }

        @DisplayName("Verify mdoc V3 beta built de pid namespace correct with minimal data")
        @Test
        void test004() {
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
            var mdoc = subject.create(data, bindingKey, statusRef, validity);

            // Then
            Map<String, Object> pidValues = readPidValues(mdoc, DE_NAMESPACE);
            assertSoftly(soft -> {
                soft.assertThat(pidValues).hasSize(11);
                soft.assertThat(pidValues).extractingByKey("age_over_12").asInstanceOf(BOOLEAN).isTrue();
                soft.assertThat(pidValues).extractingByKey("age_over_14").asInstanceOf(BOOLEAN).isTrue();
                soft.assertThat(pidValues).extractingByKey("age_over_16").asInstanceOf(BOOLEAN).isTrue();
                soft.assertThat(pidValues).extractingByKey("age_over_18").asInstanceOf(BOOLEAN).isTrue();
                soft.assertThat(pidValues).extractingByKey("age_over_21").asInstanceOf(BOOLEAN).isTrue();
                soft.assertThat(pidValues).extractingByKey("age_over_65").asInstanceOf(BOOLEAN).isFalse();
                soft.assertThat(pidValues).extractingByKey("birth_name").isEqualTo("");
                soft.assertThat(pidValues).extractingByKey("source_document_type").isEqualTo("ID");
                soft.assertThat(pidValues).doesNotContainKey("place_of_birth");
                soft.assertThat(pidValues).extractingByKey("also_known_as").isEqualTo("");
                soft.assertThat(pidValues).extractingByKey("academic_title").isEqualTo("");
                soft.assertThat(pidValues).extractingByKey("raw_eid_birth_date").isEqualTo("1964-08-12");
            });
        }

        @DisplayName("Verify birth_date is tagged as full-date")
        @Test
        void test011() {
            // Given
            var statusRef = getStatusReference();
            var data = new PIDIdentityDataBuilder().build();

            // When
            var mdoc = subject.create(data, bindingKey, statusRef, validity);

            // Then
            var mdocNode = readMdocNode(mdoc);
            var nameSpaceNode = readNameSpaceNode(mdocNode, EU_NAMESPACE);
            var nameSpaceDataElementStream = nameSpaceNode.valueStream()
                .map(MdocCredentialCreatorTestBase::decodeFromBytes)
                .map(IssuerSignedItem.Companion::fromCBOR);
            assertThat(nameSpaceDataElementStream)
                .anySatisfy(o -> {
                    assertThat(o.getElementIdentifier()).isEqualTo("birth_date");
                    assertThat(o.getElementValue()).satisfies(MdocCredentialCreatorTestBase::assertTypeIsFullDateString);
                });
        }
    }

    @DisplayName("Verify raw_eid_birth_date is tagged as full-date")
    @Test
    void test012() {
        // Given
        var statusRef = getStatusReference();
        var data = new PIDIdentityDataBuilder().build();

        // When
        var mdoc = subject.create(data, bindingKey, statusRef, validity);

        // Then
        var mdocNode = readMdocNode(mdoc);
        var nameSpaceNode = readNameSpaceNode(mdocNode, DE_NAMESPACE);
        var nameSpaceDataElementStream = nameSpaceNode.valueStream()
            .map(MdocCredentialCreatorTestBase::decodeFromBytes)
            .map(IssuerSignedItem.Companion::fromCBOR);
        assertThat(nameSpaceDataElementStream)
            .anySatisfy(o -> {
                assertThat(o.getElementIdentifier()).isEqualTo("raw_eid_birth_date");
                assertThat(o.getElementValue()).satisfies(MdocCredentialCreatorTestBase::assertTypeIsFullDateString);
            });
    }

    private StatusReference getStatusReference() {
        return new StatusReference("http://list-uri", statusIndex++);
    }
}
