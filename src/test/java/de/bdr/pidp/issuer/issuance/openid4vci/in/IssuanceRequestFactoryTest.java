/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.in;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.jwk.JWKSet;
import de.bdr.pidp.issuer.issuance.RequestUtil;
import de.bdr.pidp.issuer.issuance.config.IssuanceTestMetadata;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.config.model.CredentialIssuerMetadata;
import de.bdr.pidp.issuer.issuance.config.model.CredentialRequestEncryption;
import de.bdr.pidp.issuer.issuance.config.model.CredentialResponseEncryption;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidCredentialRequestException;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidEncryptionParametersException;
import de.bdr.pidp.issuer.issuance.openid4vci.service.RequestEncryptionService;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import org.springframework.util.MultiValueMap;
import tools.jackson.databind.json.JsonMapper;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IssuanceRequestFactoryTest {
    private static final MultiValueMap<String, String> HTTP_HEADERS = MultiValueMap.fromMultiValue(RequestUtil.HTTP_HEADER);

    private final JsonMapper jsonMapper = JsonMapper.builder().build();
    private final RequestEncryptionService reqEncMock = mock(RequestEncryptionService.class);

    @DisplayName("process not encrypted credential request")
    @Test
    void test001() {
        doReturn(new JWKSet(TestUtils.REQUEST_ENCRYPTION_KAK)).when(reqEncMock).getPrivateKeySet();
        var adapter = new IssuanceRequestFactory(reqEncMock, IssuanceTestMetadata.ISSUANCE_METADATA);

        String body = RequestUtil.getCredentialRequestBody(CredentialConfigurationID.SD_JWT_V1.getName(), RequestUtil.JWT_PROOF_TYPE, Collections.emptyList());

        var credentialRequest = adapter.getCredentialRequest(HttpMethod.POST, false, HTTP_HEADERS, body);

        assertThat(credentialRequest.getCredentialConfigurationID().getName())
            .isEqualTo(jsonMapper.readTree(body).get("credential_configuration_id").asString());
    }

    @DisplayName("Decrypt encrypted credential request")
    @Test
    void test002() {
        doReturn(new JWKSet(TestUtils.REQUEST_ENCRYPTION_KAK)).when(reqEncMock).getPrivateKeySet();
        var adapter = new IssuanceRequestFactory(reqEncMock, IssuanceTestMetadata.ISSUANCE_METADATA);

        String requestBody = RequestUtil.getCredentialRequestBody(CredentialConfigurationID.SD_JWT_V1.getName(), RequestUtil.JWT_PROOF_TYPE, Collections.emptyList());
        var body = TestUtils.generateEncryptedJWT(TestUtils.REQUEST_ENCRYPTION_PUB.toECKey(), requestBody).serialize();

        var credentialRequest = adapter.getCredentialRequest(HttpMethod.POST, true, HTTP_HEADERS, body);

        assertThat(credentialRequest.getCredentialConfigurationID().getName())
            .isEqualTo(jsonMapper.readTree(requestBody).get("credential_configuration_id").asString());
    }

    @DisplayName("Decrypt encrypted credential request with response encryption")
    @Test
    void test003() {
        doReturn(new JWKSet(TestUtils.REQUEST_ENCRYPTION_KAK)).when(reqEncMock).getPrivateKeySet();
        var adapter = new IssuanceRequestFactory(reqEncMock, IssuanceTestMetadata.ISSUANCE_METADATA);

        var resJwk = TestUtils.generateECDHEncryptionKey();
        var resEnc = EncryptionMethod.A256GCM;
        String requestBody = RequestUtil.getCredentialRequestBody(CredentialConfigurationID.SD_JWT_V1.getName(), RequestUtil.JWT_PROOF_TYPE, Collections.emptyList(), resJwk, resEnc);
        var body = TestUtils.generateEncryptedJWT(TestUtils.REQUEST_ENCRYPTION_PUB.toECKey(), requestBody).serialize();

        var credentialRequest = adapter.getCredentialRequest(HttpMethod.POST, true, HTTP_HEADERS, body);

        assertThat(credentialRequest.getCredentialConfigurationID().getName())
            .isEqualTo(jsonMapper.readTree(requestBody).get("credential_configuration_id").asString());
    }

    @DisplayName("Credential request encrypted with unknown KAK")
    @Test
    void test004() {
        doReturn(new JWKSet(TestUtils.REQUEST_ENCRYPTION_KAK)).when(reqEncMock).getPrivateKeySet();
        var adapter = new IssuanceRequestFactory(reqEncMock, IssuanceTestMetadata.ISSUANCE_METADATA);

        String requestBody = RequestUtil.getCredentialRequestBody(CredentialConfigurationID.SD_JWT_V1.getName(), RequestUtil.ATTESTATION_PROOF_TYPE, Collections.emptyList());
        var body = TestUtils.generateEncryptedJWT(TestUtils.generateECDHEncryptionKey(), requestBody).serialize();

        assertThatThrownBy(() -> adapter.getCredentialRequest(HttpMethod.POST, true, HTTP_HEADERS, body))
            .isInstanceOf(InvalidEncryptionParametersException.class);
    }

    @DisplayName("Encrypted credential request could not be decrypted")
    @Test
    void test005() {
        var adapter = new IssuanceRequestFactory(reqEncMock, IssuanceTestMetadata.ISSUANCE_METADATA);

        var body = "this..is.no.jwe";

        assertThatThrownBy(() -> adapter.getCredentialRequest(HttpMethod.POST, true, HTTP_HEADERS, body))
            .isInstanceOf(InvalidCredentialRequestException.class);
    }

    @DisplayName("Unencrypted credential request is not processed if encryption is required")
    @Test
    void test006() {
        CredentialRequestEncryption requestEncryptionMock = mock(CredentialRequestEncryption.class);
        var metadataMock = mock(CredentialIssuerMetadata.class);
        when(metadataMock.credentialRequestEncryption()).thenReturn(requestEncryptionMock);
        when(requestEncryptionMock.encryptionRequired()).thenReturn(true);

        var adapter = new IssuanceRequestFactory(reqEncMock, metadataMock);

        String body = RequestUtil.getCredentialRequestBody(CredentialConfigurationID.SD_JWT_V1.getName(), RequestUtil.JWT_PROOF_TYPE, Collections.emptyList());

        assertThatThrownBy(() -> adapter.getCredentialRequest(HttpMethod.POST, false, HTTP_HEADERS, body))
            .isInstanceOf(InvalidCredentialRequestException.class);
    }

    @DisplayName("Encrypted credential request is not processed if encryption is not supported")
    @Test
    void test007() {
        var metadataMock = mock(CredentialIssuerMetadata.class);
        when(metadataMock.credentialRequestEncryption()).thenReturn(null);

        var adapter = new IssuanceRequestFactory(reqEncMock, metadataMock);

        var requestBody = RequestUtil.getCredentialRequestBody(CredentialConfigurationID.SD_JWT_V1.getName(), RequestUtil.JWT_PROOF_TYPE, Collections.emptyList());
        var body = TestUtils.generateEncryptedJWT(TestUtils.REQUEST_ENCRYPTION_PUB.toECKey(), requestBody).serialize();

        assertThatThrownBy(() -> adapter.getCredentialRequest(HttpMethod.POST, true, HTTP_HEADERS, body))
            .isInstanceOf(InvalidCredentialRequestException.class);
    }

    @DisplayName("Credential request without response encryption params is not processed if response encryption is required")
    @Test
    void test008() {
        doReturn(new JWKSet(TestUtils.REQUEST_ENCRYPTION_KAK)).when(reqEncMock).getPrivateKeySet();
        var requestEncryptionMock = mock(CredentialRequestEncryption.class);
        var responseEncryptionMock = mock(CredentialResponseEncryption.class);
        var metadataMock = mock(CredentialIssuerMetadata.class);
        when(metadataMock.credentialRequestEncryption()).thenReturn(requestEncryptionMock);
        when(metadataMock.credentialResponseEncryption()).thenReturn(responseEncryptionMock);
        when(requestEncryptionMock.encryptionRequired()).thenReturn(true);
        when(requestEncryptionMock.encValuesSupported()).thenReturn(List.of(EncryptionMethod.A256GCM));
        when(responseEncryptionMock.encryptionRequired()).thenReturn(true);

        var adapter = new IssuanceRequestFactory(reqEncMock, metadataMock);

        var requestBody = RequestUtil.getCredentialRequestBody(CredentialConfigurationID.SD_JWT_V1.getName(), RequestUtil.JWT_PROOF_TYPE, Collections.emptyList());
        var body = TestUtils.generateEncryptedJWT(TestUtils.REQUEST_ENCRYPTION_PUB.toECKey(), requestBody).serialize();

        assertThatThrownBy(() -> adapter.getCredentialRequest(HttpMethod.POST, true, HTTP_HEADERS, body))
            .isInstanceOf(InvalidCredentialRequestException.class);
    }

    @DisplayName("Credential request with response encryption params is not processed if response encryption is not supported")
    @Test
    void test009() {
        var metadataMock = mock(CredentialIssuerMetadata.class);
        when(metadataMock.credentialResponseEncryption()).thenReturn(null);

        var adapter = new IssuanceRequestFactory(reqEncMock, metadataMock);

        var resJwk = TestUtils.generateECDHEncryptionKey();
        var resEnc = EncryptionMethod.A256GCM;
        var requestBody = RequestUtil.getCredentialRequestBody(CredentialConfigurationID.SD_JWT_V1.getName(), RequestUtil.JWT_PROOF_TYPE, Collections.emptyList(), resJwk, resEnc);
        var body = TestUtils.generateEncryptedJWT(TestUtils.REQUEST_ENCRYPTION_PUB.toECKey(), requestBody).serialize();

        assertThatThrownBy(() -> adapter.getCredentialRequest(HttpMethod.POST, true, HTTP_HEADERS, body))
            .isInstanceOf(InvalidCredentialRequestException.class);
    }

    @DisplayName("Credential request with response encryption params is not processed if request is not encrypted")
    @Test
    void test010() {
        var adapter = new IssuanceRequestFactory(reqEncMock, IssuanceTestMetadata.ISSUANCE_METADATA);

        var resJwk = TestUtils.generateECDHEncryptionKey();
        var resEnc = EncryptionMethod.A256GCM;
        var body = RequestUtil.getCredentialRequestBody(CredentialConfigurationID.SD_JWT_V1.getName(), RequestUtil.JWT_PROOF_TYPE, Collections.emptyList(), resJwk, resEnc);

        assertThatThrownBy(() -> adapter.getCredentialRequest(HttpMethod.POST, true, HTTP_HEADERS, body))
            .isInstanceOf(InvalidCredentialRequestException.class);
    }

    @DisplayName("process credential request without body")
    @ParameterizedTest
    @NullAndEmptySource
    void test011(String requestBody) {
        var metadataMock = mock(CredentialIssuerMetadata.class);
        var adapter = new IssuanceRequestFactory(reqEncMock, metadataMock);

        assertThatThrownBy(() -> adapter.getCredentialRequest(HttpMethod.POST, false, HTTP_HEADERS, requestBody))
            .isInstanceOf(InvalidCredentialRequestException.class).hasMessage("Request body is missing");
    }
}
