/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof;

import com.nimbusds.jose.JOSEObjectType;
import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.RandomUtil;
import de.bdr.pidp.issuer.clientconfiguration.ClientConfigurationService;
import de.bdr.pidp.issuer.issuance.RequestUtil;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidNonceException;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidProofException;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.OIDException;
import de.bdr.pidp.issuer.issuance.openid4vci.service.CNonceService;
import de.bdr.pidp.issuer.issuance.openid4vci.service.domain.CredentialRequest;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests.AttestationProofType;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests.JwtProofType;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.requests.ProofType;
import de.bdr.pidp.issuer.testdata.ClientIds;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import static de.bdr.pidp.issuer.issuance.ConfigTestData.ISSUANCE_CONFIG;
import static de.bdr.pidp.issuer.issuance.config.IssuanceTestMetadata.ISSUANCE_METADATA;
import static de.bdr.pidp.issuer.testdata.TestUtils.KEY_ATTESTATION_TRUST_ANCHOR;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
class KeyProofHandlerTest {
    private static final ProofType VALID_PROOF_TYPE = JwtProofType.INSTANCE;
    private static final JOSEObjectType VALID_JWT_TYPE = TestUtils.JWT_PROOF_TYPE;
    private static final JOSEObjectType INVALID_JWT_TYPE = new JOSEObjectType("invalid");
    private static final String VALID_JWT_AUDIENCE = TestUtils.ISSUER_IDENTIFIER_AUDIENCE;
    private final int maxKeysSize = Objects.requireNonNull(ISSUANCE_METADATA.batchCredentialIssuance()).batchSize();
    private static final CNonceService cNonceService = mock(CNonceService.class);
    private static final ClientConfigurationService clientConfigurationService = mock(ClientConfigurationService.class);
    private final JwtKeyProofHandler jwtProofHandler = new JwtKeyProofHandler(new KeyProofService(ISSUANCE_CONFIG, ISSUANCE_METADATA, cNonceService), ISSUANCE_METADATA);
    private final AttestationKeyProofHandler attestationProofHandler = new AttestationKeyProofHandler(clientConfigurationService, ISSUANCE_CONFIG, ISSUANCE_METADATA, cNonceService);

    private static CredentialRequest initKeyProofRequest(Nonce nonce, JOSEObjectType jwtType, String jwtIssuer, String jwtAudience, Instant jwtIssueTime, String jwtNonce) {
        doReturn(false).when(cNonceService).consume(any());
        doReturn(true).when(cNonceService).consume(nonce.nonce());

        var jwt = TestUtils.buildProofJwt(jwtType, jwtIssuer, jwtAudience, jwtIssueTime, jwtNonce);
        return RequestUtil.createCredentialRequest(CredentialConfigurationID.SD_JWT_V2, VALID_PROOF_TYPE, List.of(jwt.serialize()));
    }

    private static CredentialRequest initEmptyKeyProofRequest() {
        var nonce = new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity());

        doReturn(true).when(cNonceService).consume(nonce.nonce());

        return RequestUtil.createCredentialRequest(CredentialConfigurationID.SD_JWT_V2, VALID_PROOF_TYPE, Collections.emptyList());
    }

    private static CredentialRequest initKeyProofRequest(Nonce nonce, JOSEObjectType jwtType, String jwtIssuer, String jwtAudience, Instant jwtIssueTime, String jwtNonce, int nrProofs) {
        doReturn(true).when(cNonceService).consume(nonce.nonce());

        var jwt = TestUtils.buildProofJwt(jwtType, jwtIssuer, jwtAudience, jwtIssueTime, jwtNonce);
        return RequestUtil.createCredentialRequest(CredentialConfigurationID.SD_JWT_V2, VALID_PROOF_TYPE, Collections.nCopies(nrProofs, jwt.serialize()));
    }

    private static CredentialRequest initValidKeyProofRequest(String clientId) {
        var nonce = new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity());
        return initKeyProofRequest(nonce, VALID_JWT_TYPE, clientId, VALID_JWT_AUDIENCE, Instant.now(), nonce.nonce());
    }

    private static CredentialRequest initValidKeyProofRequest(String clientId, int nrProofs) {
        var nonce = new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity());
        return initKeyProofRequest(nonce, VALID_JWT_TYPE, clientId, VALID_JWT_AUDIENCE, Instant.now(), nonce.nonce(), nrProofs);
    }

    private static CredentialRequest initInvalidKeyProofRequestInvalidJwtType(String clientId) {
        var nonce = new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity());
        return initKeyProofRequest(nonce, INVALID_JWT_TYPE, clientId, VALID_JWT_AUDIENCE, Instant.now(), nonce.nonce());
    }

    private static CredentialRequest initInvalidKeyProofRequestInvalidIssuer() {
        var nonce = new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity());
        return initKeyProofRequest(nonce, VALID_JWT_TYPE, "different", VALID_JWT_AUDIENCE, Instant.now(), nonce.nonce());
    }

    private static CredentialRequest initInvalidKeyProofRequestInvalidAudience(String clientId) {
        var nonce = new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity());
        return initKeyProofRequest(nonce, VALID_JWT_TYPE, clientId, "invalid", Instant.now(), nonce.nonce());
    }

    private static CredentialRequest initInvalidKeyProofRequestIssuanceInFuture(String clientId) {
        var nonce = new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity());
        return initKeyProofRequest(nonce, VALID_JWT_TYPE, clientId, VALID_JWT_AUDIENCE, Instant.now().plus(ISSUANCE_CONFIG.getProofTimeTolerance()).plusSeconds(10), nonce.nonce());
    }

    private static CredentialRequest initInvalidKeyProofRequestIssuanceTooOld(String clientId) {
        var nonce = new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity());
        return initKeyProofRequest(nonce, VALID_JWT_TYPE, clientId, VALID_JWT_AUDIENCE, Instant.now().minus(ISSUANCE_CONFIG.getProofTimeTolerance()).minus(ISSUANCE_CONFIG.getProofValidity()).minusSeconds(10), nonce.nonce());
    }

    private static CredentialRequest initInvalidKeyProofRequestInvalidNonce(String clientId) {
        var nonce = new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity());
        return initKeyProofRequest(nonce, VALID_JWT_TYPE, clientId, VALID_JWT_AUDIENCE, Instant.now(), "nonce");
    }

    private static CredentialRequest initKeyAttestationProofRequest(String clientId, Nonce nonce, String jwtNonce) {
        doReturn(false).when(cNonceService).consume(any());
        doReturn(true).when(cNonceService).consume(nonce.nonce());
        doReturn(KEY_ATTESTATION_TRUST_ANCHOR).when(clientConfigurationService).getKeyAttestationCerts(UUID.fromString(clientId));

        var jwt = TestUtils.getValidKeyAttestationJwt(jwtNonce);
        return RequestUtil.createCredentialRequest(CredentialConfigurationID.SD_JWT_V2, AttestationProofType.INSTANCE, List.of(jwt.serialize()));
    }

    private static CredentialRequest initKeyAttestationProofRequest(String clientId, Nonce nonce, String jwtNonce, int nrKeys, int nrProofs) {
        doReturn(false).when(cNonceService).consume(any());
        doReturn(true).when(cNonceService).consume(nonce.nonce());
        doReturn(KEY_ATTESTATION_TRUST_ANCHOR).when(clientConfigurationService).getKeyAttestationCerts(UUID.fromString(clientId));

        var jwt = TestUtils.getValidKeyAttestationJwt(jwtNonce, nrKeys);
        return RequestUtil.createCredentialRequest(CredentialConfigurationID.SD_JWT_V2, AttestationProofType.INSTANCE, Collections.nCopies(nrProofs, jwt.serialize()));
    }

    @DisplayName("Verify proof valid on credential request")
    @Test
    void test001() {
        var clientId = ClientIds.validClientIdForSelfSigned().toString();
        var request = initValidKeyProofRequest(clientId);

        var jwks = jwtProofHandler.validateAndGetJwks(request, clientId);

        var expectedJwk = TestUtils.RELYING_PARTY_PUBLIC_KEY;
        assertThat(jwks).containsExactly(expectedJwk);
    }

    @DisplayName("Verify exception when jwt type is invalid on credential request")
    @Test
    void test002() {
        var clientId = ClientIds.validClientIdForSelfSigned().toString();
        var request = initInvalidKeyProofRequestInvalidJwtType(clientId);

        assertThatThrownBy(() -> jwtProofHandler.validateAndGetJwks(request, clientId))
                .hasMessage("Proof JWT type mismatch, expected to be openid4vci-proof+jwt")
                .asInstanceOf(InstanceOfAssertFactories.type(InvalidProofException.class))
                .extracting(OIDException::getErrorCode).isEqualTo("invalid_proof");
    }

    @DisplayName("Verify exception when issuer is invalid on credential request")
    @Test
    void test003() {
        var clientId = ClientIds.validClientIdForSelfSigned().toString();
        var request = initInvalidKeyProofRequestInvalidIssuer();

        assertThatThrownBy(() -> jwtProofHandler.validateAndGetJwks(request, clientId))
                .hasMessage("Proof JWT issuer invalid")
                .asInstanceOf(InstanceOfAssertFactories.type(InvalidProofException.class))
                .extracting(OIDException::getErrorCode).isEqualTo("invalid_proof");
    }

    @DisplayName("Verify exception when audience is invalid on credential request")
    @Test
    void test004() {
        var clientId = ClientIds.validClientIdForSelfSigned().toString();
        var request = initInvalidKeyProofRequestInvalidAudience(clientId);

        assertThatThrownBy(() -> jwtProofHandler.validateAndGetJwks(request, clientId))
                .hasMessage("Proof JWT audience invalid")
                .asInstanceOf(InstanceOfAssertFactories.type(InvalidProofException.class))
                .extracting(OIDException::getErrorCode).isEqualTo("invalid_proof");
    }

    @DisplayName("Verify exception when issuance is in the future on credential request")
    @Test
    void test005() {
        var clientId = ClientIds.validClientIdForSelfSigned().toString();
        var request = initInvalidKeyProofRequestIssuanceInFuture(clientId);

        assertThatThrownBy(() -> jwtProofHandler.validateAndGetJwks(request, clientId))
                .hasMessage("Proof JWT is issued in the future")
                .asInstanceOf(InstanceOfAssertFactories.type(InvalidProofException.class))
                .extracting(OIDException::getErrorCode).isEqualTo("invalid_proof");
    }

    @DisplayName("Verify exception when issuance is too old on credential request")
    @Test
    void test006() {
        var clientId = ClientIds.validClientIdForSelfSigned().toString();
        var request = initInvalidKeyProofRequestIssuanceTooOld(clientId);

        assertThatThrownBy(() -> jwtProofHandler.validateAndGetJwks(request, clientId))
                .hasMessage("Proof JWT issuance is too old")
                .asInstanceOf(InstanceOfAssertFactories.type(InvalidProofException.class))
                .extracting(OIDException::getErrorCode).isEqualTo("invalid_proof");
    }

    @DisplayName("Verify exception when nonce is invalid on credential request")
    @Test
    void test007() {
        var clientId = ClientIds.validClientIdForSelfSigned().toString();
        var request = initInvalidKeyProofRequestInvalidNonce(clientId);

        assertThatThrownBy(() -> jwtProofHandler.validateAndGetJwks(request, clientId))
                .hasMessage("Proof JWT credential nonce invalid")
                .asInstanceOf(InstanceOfAssertFactories.type(InvalidNonceException.class))
                .extracting(OIDException::getErrorCode).isEqualTo("invalid_nonce");

    }

    @DisplayName("Verify exception when missing client id")
    @Test
    void test008() {
        var clientId = ClientIds.validClientIdForSelfSigned().toString();
        var request = initValidKeyProofRequest(clientId);

        assertThatThrownBy(() -> jwtProofHandler.validateAndGetJwks(request, null))
                .hasMessage("clientId not found")
                .isInstanceOf(PidServerException.class);
    }

    @DisplayName("Verify exception when proofs is empty")
    @Test
    void test009() {
        var clientId = ClientIds.validClientIdForSelfSigned().toString();
        var request = initEmptyKeyProofRequest();

        assertThatThrownBy(() -> jwtProofHandler.validateAndGetJwks(request, clientId))
                .hasMessage("Proof is missing")
                .asInstanceOf(InstanceOfAssertFactories.type(InvalidProofException.class))
                .extracting(OIDException::getErrorCode).isEqualTo("invalid_proof");
    }

    @DisplayName("Verify proof valid on credential request")
    @Test
    void test010() {
        var clientId = ClientIds.validClientIdForSelfSigned().toString();
        var request = initValidKeyProofRequest(clientId, 2);

        var jwks = jwtProofHandler.validateAndGetJwks(request, clientId);


        var expectedJwk = TestUtils.RELYING_PARTY_PUBLIC_KEY;
        assertThat(jwks).containsExactly(expectedJwk, expectedJwk);
    }

    @DisplayName("Verify exception when more proofs provided than allowed")
    @Test
    void test011() {
        var invalidCountProofs = maxKeysSize + 1;
        var clientId = ClientIds.validClientIdForSelfSigned().toString();
        var request = initValidKeyProofRequest(clientId, invalidCountProofs);

        assertThatThrownBy(() -> jwtProofHandler.validateAndGetJwks(request, clientId))
                .hasMessage("Too many proofs")
                .asInstanceOf(InstanceOfAssertFactories.type(InvalidProofException.class))
                .extracting(OIDException::getErrorCode).isEqualTo("invalid_proof");
    }

    @DisplayName("Verify key attestation proof valid on credential request")
    @Test
    void test012() {
        var clientId = ClientIds.validClientIdForSelfSigned().toString();
        var nonce = new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity());
        var request = initKeyAttestationProofRequest(clientId, nonce, nonce.nonce());

        var jwks = attestationProofHandler.validateAndGetJwks(request, clientId);

        var expectedJwk = TestUtils.ATTESTED_KEYS.getFirst();
        assertThat(jwks).containsExactly(expectedJwk);
    }

    @DisplayName("Verify key attestation proof valid on credential batch request with max keys size")
    @Test
    void test013() {
        var clientId = ClientIds.validClientIdForSelfSigned().toString();
        var nonce = new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity());
        var request = initKeyAttestationProofRequest(clientId, nonce, nonce.nonce(), maxKeysSize, 1);

        var jwks = attestationProofHandler.validateAndGetJwks(request, clientId);

        var expectedJwk = TestUtils.ATTESTED_KEYS.getFirst();
        assertThat(jwks).containsAll(Collections.nCopies(maxKeysSize, expectedJwk));
    }

    @DisplayName("Verify exception with key attestation proof when missing client id")
    @Test
    void test014() {
        var clientId = ClientIds.validClientIdForSelfSigned().toString();
        var nonce = new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity());
        var request = initKeyAttestationProofRequest(clientId, nonce, nonce.nonce());

        assertThatThrownBy(() -> attestationProofHandler.validateAndGetJwks(request, null))
                .hasMessage("clientId not found")
                .isInstanceOf(PidServerException.class);
    }

    @DisplayName("Verify key attestation proofs exception when more than one proof provided")
    @Test
    void test015() {
        var clientId = ClientIds.validClientIdForSelfSigned().toString();
        var nonce = new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity());
        var invalidCountKeyAttestationProofs = 2;
        var request = initKeyAttestationProofRequest(clientId, nonce, nonce.nonce(), 1, invalidCountKeyAttestationProofs);

        assertThatThrownBy(() -> attestationProofHandler.validateAndGetJwks(request, clientId))
                .hasMessage("Too many proofs")
                .asInstanceOf(InstanceOfAssertFactories.type(InvalidProofException.class))
                .extracting(OIDException::getErrorCode).isEqualTo("invalid_proof");
    }

    @DisplayName("Verify key attestation proof exception when more keys provided than allowed")
    @Test
    void test016() {
        var clientId = ClientIds.validClientIdForSelfSigned().toString();
        var nonce = new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity());
        var invalidKeyAttestationKeysSize = maxKeysSize + 1;
        var request = initKeyAttestationProofRequest(clientId, nonce, nonce.nonce(), invalidKeyAttestationKeysSize, 1);

        assertThatThrownBy(() -> attestationProofHandler.validateAndGetJwks(request, clientId))
                .hasMessage("Too many keys")
                .asInstanceOf(InstanceOfAssertFactories.type(InvalidProofException.class))
                .extracting(OIDException::getErrorCode).isEqualTo("invalid_proof");
    }

    @DisplayName("Verify key attestation proof exception when credential configuration id not supported")
    @Test
    void test017() {
        var clientId = ClientIds.validClientIdForSelfSigned().toString();
        var nonce = new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity());
        var request = initKeyAttestationProofRequest(clientId, nonce, nonce.nonce());

        var original = ReflectionTestUtils.getField(attestationProofHandler, "keyAttestationVerifiers");
        try {
            ReflectionTestUtils.setField(attestationProofHandler, "keyAttestationVerifiers", Collections.emptyMap());

            assertThatThrownBy(() -> attestationProofHandler.validateAndGetJwks(request, clientId))
                .hasMessage("Attestation proof not supported for given credential_configuration_id")
                .asInstanceOf(InstanceOfAssertFactories.type(InvalidProofException.class))
                .extracting(OIDException::getErrorCode).isEqualTo("invalid_proof");
        } finally {
            ReflectionTestUtils.setField(attestationProofHandler, "keyAttestationVerifiers", original);
        }
    }
}
