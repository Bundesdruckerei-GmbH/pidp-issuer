/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.service;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectReader;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.dataformat.cbor.CBORMapper;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoField;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static de.bdr.pidp.issuer.base.FileResourceHelper.getFileInputStream;
import static de.bdr.pidp.issuer.issuance.ConfigTestData.ISSUANCE_CONFIG;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

class MdocCredentialCreatorTestBase extends CredentialCreatorTestBase {
    protected static final CBORMapper CBOR_MAPPER = new CBORMapper();
    protected static final ZoneId LOCAL_ZONE = ZoneId.of("Europe/Berlin");
    protected static final String DOC_TYPE = "eu.europa.ec.eudi.pid.1";
    protected static final String EU_NAMESPACE = DOC_TYPE;
    protected static final String DE_NAMESPACE = "eu.europa.ec.eudi.pid.de.1";

    protected static byte[] getDecodedString(String encoded) {
        return Base64.getUrlDecoder().decode(encoded);
    }

    protected static void assertTypeIsStandardDateTimeString(CBORObject v) {
        assertThat(v.getType()).isEqualTo(CBORType.TextString);
        assertThat(v.isTagged()).isTrue();
        assertThat(v.getMostInnerTag().ToInt32Checked()).isZero();
        final AtomicReference<Instant> i = new AtomicReference<>();
        assertThatNoException().isThrownBy(() -> i.set(Instant.parse(v.AsString())));
        assertThat(i.get().get(ChronoField.MILLI_OF_SECOND)).isZero();
    }

    protected static void assertTypeIsFullDateString(CBORObject v) {
        assertThat(v.getType()).isEqualTo(CBORType.TextString);
        assertThat(v.isTagged()).isTrue();
        assertThat(v.getMostInnerTag().ToInt32Checked()).isEqualTo(1004);
        assertThatNoException().isThrownBy(() -> DateTimeFormatter.ISO_LOCAL_DATE.parse(v.AsString()));
    }

    protected static List<? extends Certificate> getCertificateChain(JsonNode unprotectedHeaderParameters) throws CertificateException {
        JsonNode x5ChainParameter = unprotectedHeaderParameters.get(String.valueOf(CoseHeaderParameters.X5CHAIN.label));
        byte[] x5ChainDer = x5ChainParameter.binaryValue();
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return new ArrayList<>(certificateFactory.generateCertificates(new ByteArrayInputStream(x5ChainDer)));
    }

    protected static PublicKey getSignerPub() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance("pkcs12");
        ks.load(getFileInputStream(ISSUANCE_CONFIG.getSignerPath()), ISSUANCE_CONFIG.getSignerPassword().toCharArray());
        return ks.getCertificate(ISSUANCE_CONFIG.getSignerAlias()).getPublicKey();
    }

    protected static JsonNode readNameSpaceNode(JsonNode mdoc, String nameSpace) {
        var nameSpacesNode = mdoc.get("nameSpaces");
        assertThat(nameSpacesNode.isObject()).isTrue();
        var nameSpaceNode = nameSpacesNode.get(nameSpace);
        assertThat(nameSpaceNode.isArray()).isTrue();
        return nameSpaceNode;
    }

    protected static JsonNode readMdocNode(String mdoc) {
        byte[] decodedMdoc = getDecodedString(mdoc);
        return CBOR_MAPPER.readTree(decodedMdoc);
    }

    protected static ArrayNode readIssuerAuthNode(JsonNode mdocNode) {
        var issuerAuthNode = mdocNode.get("issuerAuth");
        assertThat(issuerAuthNode.isArray()).isTrue();
        return issuerAuthNode.asArray();
    }

    protected static JsonNode readMSOBinaryNode(ArrayNode issuerAuthNode) {
        assertThat(issuerAuthNode).hasSize(4);
        var msoNode = issuerAuthNode.get(2);
        assertThat(msoNode.isBinary()).isTrue();
        return msoNode;
    }

    protected static JsonNode readMSONode(JsonNode msoBinaryNode) {
        var wrappedMSONode = CBOR_MAPPER.readTree(msoBinaryNode.binaryValue());
        assertThat(wrappedMSONode.isBinary()).isTrue();
        var msoNode = CBOR_MAPPER.readTree(wrappedMSONode.binaryValue());
        assertThat(msoNode.isObject()).isTrue();
        return msoNode;
    }

    protected static CBORObject readMSO(JsonNode msoNode) {
        CBORObject msoBStr = MdocCredentialCreatorTestBase.decodeFromBytes(msoNode);
        assertThat(msoBStr.isTagged()).isTrue();
        return MdocCredentialCreatorTestBase.decodeFromBstr(msoBStr);
    }

    private static CBORObject decodeFromBstr(CBORObject o) {
        return CBORObject.DecodeFromBytes(o.GetByteString());
    }

    protected static CBORObject decodeFromBytes(JsonNode n) {
        return CBORObject.DecodeFromBytes(n.binaryValue());
    }

    protected static Map<String, Object> readPidValues(String mdoc, String namespace) {
        var mdocNode = readMdocNode(mdoc);
        var jsonNode = readNameSpaceNode(mdocNode, namespace);
        ObjectReader reader = CBOR_MAPPER.readerFor(new TypeReference<List<byte[]>>() {
        });
        List<byte[]> list = reader.readValue(jsonNode);
        return list.stream().map(MdocCredentialCreatorTestBase::getDecodedMdocValue).collect(Collectors.toMap(
            DecodedMdocPidValue::elementIdentifier, DecodedMdocPidValue::elementValue));
    }

    private static DecodedMdocPidValue getDecodedMdocValue(byte[] cbor) {
        return CBOR_MAPPER.readValue(cbor, DecodedMdocPidValue.class);
    }

    /**
     * CBOR Object Signing and Encryption header parameters according to
     * <a href="https://www.iana.org/assignments/cose/cose.xhtml">CBOR Object Signing and Encryption (COSE)</a>
     */
    protected enum CoseHeaderParameters {
        ALG(1), X5CHAIN(33);

        final int label;

        CoseHeaderParameters(int label) {
            this.label = label;
        }
    }

    /**
     * CBOR Object Signing and Encryption algorithms according to
     * <a href="https://www.iana.org/assignments/cose/cose.xhtml">CBOR Object Signing and Encryption (COSE)</a>
     */
    protected enum CoseAlgorithms {
        ECDSA(-7);

        final int value;

        CoseAlgorithms(int value) {
            this.value = value;
        }
    }

    protected enum CoseKeyTypes {
        EC2(2);

        final int value;

        CoseKeyTypes(int value) {
            this.value = value;
        }
    }

    protected enum CoseKeyCommonParameters {
        KTY(1), X(-2), Y(-3);

        final int label;

        CoseKeyCommonParameters(int label) {
            this.label = label;
        }

        String labelStr() {
            return String.valueOf(label);
        }
    }

    private record DecodedMdocPidValue(String random, int digestID, String elementIdentifier, Object elementValue) {
    }
}
