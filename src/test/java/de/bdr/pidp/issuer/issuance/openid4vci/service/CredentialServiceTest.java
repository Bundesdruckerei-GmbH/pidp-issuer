/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.token.DPoPTokenError;
import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.base.RandomUtil;
import de.bdr.pidp.issuer.base.constants.AccessTokenClaims;
import de.bdr.pidp.issuer.base.identitydata.IdentityData;
import de.bdr.pidp.issuer.issuance.RequestUtil;
import de.bdr.pidp.issuer.issuance.config.IssuanceTestMetadata;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.config.model.CredentialIssuerMetadata;
import de.bdr.pidp.issuer.issuance.core.CredentialCreationService;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidIdentityDataException;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidProofException;
import de.bdr.pidp.issuer.issuance.openid4vci.out.authorization.AuthorizationAdapter;
import de.bdr.pidp.issuer.issuance.openid4vci.out.identification.IdentificationAdapter;
import de.bdr.pidp.issuer.issuance.openid4vci.out.identification.InvalidSeedCredentialException;
import de.bdr.pidp.issuer.issuance.openid4vci.service.domain.CredentialRequest;
import de.bdr.pidp.issuer.issuance.openid4vci.service.dpop.CredentialRequestDPoPValidator;
import de.bdr.pidp.issuer.issuance.openid4vci.service.dpop.IssuanceDPoPValidationException;
import de.bdr.pidp.issuer.issuance.openid4vci.service.dpop.MissingDPoPNonceException;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.AttestationKeyProofHandler;
import de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof.JwtKeyProofHandler;
import de.bdr.pidp.issuer.testdata.ClientIds;
import de.bdr.pidp.issuer.testdata.TestAccessTokenIssuer;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static de.bdr.pidp.issuer.issuance.ConfigTestData.ISSUANCE_CONFIG;
import static de.bdr.pidp.issuer.testdata.PidTestData.TEST_IDENTITY_DATA;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialServiceTest {

    private static final JWTClaimsSet AT_CLAIMS = TestAccessTokenIssuer.defaultClaims(Base64URL.encode("dummy")).build();
    private static final String ACCESS_TOKEN_ID;
    private static final String SEED_CREDENTIAL_REF;

    private static final JOSEObjectType VALID_JWT_TYPE = TestUtils.JWT_PROOF_TYPE;
    private static final String VALID_JWT_AUDIENCE = TestUtils.ISSUER_IDENTIFIER_AUDIENCE;
    private static final Nonce NONCE = new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity());

    static {
        try {
            ACCESS_TOKEN_ID = AT_CLAIMS.getJWTID();
            SEED_CREDENTIAL_REF = AT_CLAIMS.getStringClaim(AccessTokenClaims.SEED_CREDENTIAL_REFERENCE);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    @Mock
    private AuthorizationAdapter authorizationAdapter;

    @Mock
    private IdentificationAdapter identificationAdapter;

    @Spy
    private CredentialIssuerMetadata issuerMetadata = IssuanceTestMetadata.ISSUANCE_METADATA;

    @Mock
    private CredentialConfigurationIDValidator configurationIDValidator;

    @Mock
    private CredentialRequestDPoPValidator credentialRequestDPoPValidator;

    @Mock
    private AccessTokenValidator accessTokenValidator;

    @Mock
    private ResponseEncryptionParameterValidator responseEncryptionParameterValidator;

    @Mock
    private CredentialCreationService credentialCreationService;

    @InjectMocks
    private CredentialService credentialService;

    private AttestationKeyProofHandler attestationKeyProofHandlerMock;

    @BeforeEach
    void setupMocks() {
        JwtKeyProofHandler jwtKeyProofHandlerMock = mock(JwtKeyProofHandler.class);
        attestationKeyProofHandlerMock = mock(AttestationKeyProofHandler.class);

        ReflectionTestUtils.setField(credentialService, "attestationKeyProofHandler", attestationKeyProofHandlerMock);
        ReflectionTestUtils.setField(credentialService, "jwtKeyProofHandler", jwtKeyProofHandlerMock);

        Mockito.lenient().doReturn(AT_CLAIMS).when(accessTokenValidator).validate(any(), any());
    }

    @Test
    void processRequestWithHandlerException() {
        // given
        var request = RequestUtil.createCredentialRequest(CredentialConfigurationID.SD_JWT_V2, Collections.emptyList());

        when(authorizationAdapter.getDPoPNonce(anyString())).thenReturn(new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity()));
        when(authorizationAdapter.retrieveSeedCredential(anyString())).thenReturn("seedCredential");
        when(identificationAdapter.verifySeedCredentialAndGetIdentityData(anyString())).thenReturn(TEST_IDENTITY_DATA);
        doThrow(new InvalidProofException("error"))
            .when(attestationKeyProofHandlerMock)
            .validateAndGetJwks(any(CredentialRequest.class), any());

        // when
        Assertions.assertThatThrownBy(() -> credentialService.processCredentialRequest(request))
            .isInstanceOf(InvalidProofException.class);

        // then
        verify(authorizationAdapter).getDPoPNonce(ACCESS_TOKEN_ID);
        verify(authorizationAdapter).retrieveSeedCredential(SEED_CREDENTIAL_REF);
    }

    @ParameterizedTest
    @EnumSource(CredentialConfigurationID.class)
    void shouldProcessSingleIssuance(CredentialConfigurationID version) {
        // given
        var holderBindingKey = TestUtils.generateEcKey();

        var request = RequestUtil.createCredentialRequest(version, Collections.emptyList());

        // when
        when(authorizationAdapter.getDPoPNonce(anyString())).thenReturn(new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity()));
        when(authorizationAdapter.retrieveSeedCredential(anyString())).thenReturn("seedCredential");
        when(attestationKeyProofHandlerMock.validateAndGetJwks(any(CredentialRequest.class), any())).thenReturn(List.of(holderBindingKey.toPublicJWK()));
        when(credentialCreationService.buildCredentials(any(), any(), any(), any())).thenReturn(List.of("credential"));
        when(identificationAdapter.verifySeedCredentialAndGetIdentityData(anyString())).thenReturn(TEST_IDENTITY_DATA);

        var response = credentialService.processCredentialRequest(request);

        // then
        verify(authorizationAdapter).getDPoPNonce(ACCESS_TOKEN_ID);
        verify(authorizationAdapter).retrieveSeedCredential(SEED_CREDENTIAL_REF);
        assertThat(response.serializedCredentials()).containsExactly("credential");
    }

    @ParameterizedTest
    @EnumSource(CredentialConfigurationID.class)
    void shouldProcessBatchIssuance(CredentialConfigurationID version) {
        // given
        var holderBindingKey = TestUtils.generateEcKey();

        var jwt = TestUtils.buildProofJwt(VALID_JWT_TYPE, ClientIds.validClientIdForSelfSigned().toString(), VALID_JWT_AUDIENCE, Instant.now(), NONCE.nonce());
        var proofs = Collections.nCopies(2, jwt.serialize());
        var request = RequestUtil.createCredentialRequest(version, proofs);

        // when
        when(authorizationAdapter.getDPoPNonce(anyString())).thenReturn(new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity()));
        when(authorizationAdapter.retrieveSeedCredential(anyString())).thenReturn("seedCredential");
        when(attestationKeyProofHandlerMock.validateAndGetJwks(any(CredentialRequest.class), any())).thenReturn(Collections.nCopies(2, holderBindingKey.toPublicJWK()));
        when(credentialCreationService.buildCredentials(any(), any(), any(), any())).thenReturn(List.of("credential", "credential2"));
        when(identificationAdapter.verifySeedCredentialAndGetIdentityData(anyString())).thenReturn(TEST_IDENTITY_DATA);

        var response = credentialService.processCredentialRequest(request);

        // then
        verify(authorizationAdapter).getDPoPNonce(ACCESS_TOKEN_ID);
        verify(authorizationAdapter).retrieveSeedCredential(SEED_CREDENTIAL_REF);
        assertThat(response.serializedCredentials()).containsExactly("credential", "credential2");
    }

    @ParameterizedTest
    @EnumSource(CredentialConfigurationID.class)
    void shouldProcessSingleIssuanceWithResponseEncryption(CredentialConfigurationID version) {
        // given
        var holderBindingKey = TestUtils.generateEcKey();

        var reqEncKAKey = TestUtils.generateECDHEncryptionKey();
        var request = RequestUtil.createCredentialRequest(version, Collections.emptyList(), reqEncKAKey, EncryptionMethod.A256GCM);

        // when
        when(authorizationAdapter.getDPoPNonce(anyString())).thenReturn(new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity()));
        when(authorizationAdapter.retrieveSeedCredential(anyString())).thenReturn("seedCredential");
        when(attestationKeyProofHandlerMock.validateAndGetJwks(any(CredentialRequest.class), any())).thenReturn(List.of(holderBindingKey.toPublicJWK()));
        when(credentialCreationService.buildCredentials(any(), any(), any(), any())).thenReturn(List.of("credential"));
        when(identificationAdapter.verifySeedCredentialAndGetIdentityData(anyString())).thenReturn(TEST_IDENTITY_DATA);
        when(responseEncryptionParameterValidator.validate(any(), any())).thenReturn((JWEAlgorithm) reqEncKAKey.getAlgorithm());

        var response = credentialService.processCredentialRequestWithResponseEnc(request);

        // then
        verify(authorizationAdapter).getDPoPNonce(ACCESS_TOKEN_ID);
        verify(authorizationAdapter).retrieveSeedCredential(SEED_CREDENTIAL_REF);
        assertThat(response.serializedCredentials()).containsExactly("credential");
        assertThat(response.resEncKAKey()).isEqualTo(reqEncKAKey);
        assertThat(response.encMethod()).isEqualTo(EncryptionMethod.A256GCM);
        assertThat(response.resEncAlgorithm()).isEqualTo(JWEAlgorithm.ECDH_ES);
    }

    @Test
    void processRequestWithSeedVerificationFailed() {
        // given
        var request = RequestUtil.createCredentialRequest(CredentialConfigurationID.SD_JWT_V2, Collections.emptyList());

        when(authorizationAdapter.getDPoPNonce(anyString())).thenReturn(new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity()));
        when(authorizationAdapter.retrieveSeedCredential(anyString())).thenReturn("seedCredential");
        when(identificationAdapter.verifySeedCredentialAndGetIdentityData(anyString())).thenThrow(new InvalidSeedCredentialException("Invalid", new Exception()));

        // when
        Assertions.assertThatThrownBy(() -> credentialService.processCredentialRequest(request))
            .isInstanceOf(InvalidIdentityDataException.class)
            .hasMessage("Seed Credential verification failed.")
            .hasFieldOrPropertyWithValue("errorCode", "credential_request_denied");

        // then
        verify(authorizationAdapter).getDPoPNonce(ACCESS_TOKEN_ID);
        verify(authorizationAdapter).retrieveSeedCredential(SEED_CREDENTIAL_REF);
        verify(identificationAdapter).verifySeedCredentialAndGetIdentityData(anyString());
    }

    @Test
    void processRequestWithInvalidIdentityDataException() {
        // given
        var request = RequestUtil.createCredentialRequest(CredentialConfigurationID.SD_JWT_V2, Collections.emptyList());
        IdentityData invalidIdentityData = new IdentityData("INVALID", null, "2099-12-31", null, null,
            null, null, null, null, null, null,
            null, null);

        when(authorizationAdapter.getDPoPNonce(anyString())).thenReturn(new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity()));
        when(authorizationAdapter.retrieveSeedCredential(anyString())).thenReturn("seedCredential");
        when(identificationAdapter.verifySeedCredentialAndGetIdentityData(anyString())).thenReturn(invalidIdentityData);

        // when
        Assertions.assertThatThrownBy(() -> credentialService.processCredentialRequest(request))
            .isInstanceOf(InvalidIdentityDataException.class)
            .hasMessage("Identity data validation failed.")
            .hasFieldOrPropertyWithValue("errorCode", "credential_request_denied");

        // then
        verify(authorizationAdapter).getDPoPNonce(ACCESS_TOKEN_ID);
        verify(authorizationAdapter).retrieveSeedCredential(SEED_CREDENTIAL_REF);
        verify(identificationAdapter).verifySeedCredentialAndGetIdentityData("seedCredential");
    }

    @Test
    void processRequestWithDPoPValidationFailureWithInvalidDPoPValidationException() {
        // given
        var request = RequestUtil.createCredentialRequest(CredentialConfigurationID.SD_JWT_V2, Collections.emptyList());

        when(authorizationAdapter.getDPoPNonce(anyString())).thenReturn(new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity()));
        doThrow(new IssuanceDPoPValidationException(DPoPTokenError.INVALID_DPOP_PROOF))
            .when(credentialRequestDPoPValidator).validateResourceRequestDPoPProof(any(), any(), any(), any(), any());

        // when
        Assertions.assertThatThrownBy(() -> credentialService.processCredentialRequest(request))
            .isInstanceOf(IssuanceDPoPValidationException.class)
            .hasFieldOrPropertyWithValue("errorCode", "invalid_dpop_proof");

        // then
        verify(authorizationAdapter).getDPoPNonce(ACCESS_TOKEN_ID);
        verify(authorizationAdapter, never()).retrieveSeedCredential(SEED_CREDENTIAL_REF);
    }

    @Test
    void processRequestWithDPoPValidationFailureWithMissingDPoPNonceException() {
        // given
        var request = RequestUtil.createCredentialRequest(CredentialConfigurationID.SD_JWT_V2, Collections.emptyList());

        when(authorizationAdapter.provideAndStore(anyString())).thenReturn(new Nonce(RandomUtil.randomString(), Duration.ofMinutes(1)));
        when(authorizationAdapter.getDPoPNonce(anyString())).thenReturn(new Nonce(RandomUtil.randomString(), ISSUANCE_CONFIG.getProofValidity()));
        doThrow(new MissingDPoPNonceException(Set.of(JWSAlgorithm.ES384)))
            .when(credentialRequestDPoPValidator).validateResourceRequestDPoPProof(any(), any(), any(), any(), any());

        // when
        Assertions.assertThatThrownBy(() -> credentialService.processCredentialRequest(request))
            .isInstanceOf(IssuanceDPoPValidationException.class)
            .hasFieldOrPropertyWithValue("errorCode", "use_dpop_nonce");

        // then
        verify(authorizationAdapter).getDPoPNonce(ACCESS_TOKEN_ID);
        verify(authorizationAdapter, never()).retrieveSeedCredential(SEED_CREDENTIAL_REF);
    }
}
