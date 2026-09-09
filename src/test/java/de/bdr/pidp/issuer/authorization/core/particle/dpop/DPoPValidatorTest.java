/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle.dpop;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSession;
import de.bdr.pidp.issuer.authorization.core.exception.DPoPValidationException;
import de.bdr.pidp.issuer.authorization.core.exception.OAuthException;
import de.bdr.pidp.issuer.authorization.core.particle.keyattestation.DPoPKeyAttestationVerifier;
import de.bdr.pidp.issuer.authorization.core.service.DPoPNonceService;
import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.base.RandomUtil;
import de.bdr.pidp.issuer.clientconfiguration.ClientConfigurationService;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.mockito.Spy;
import org.springframework.http.HttpMethod;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static de.bdr.pidp.issuer.authorization.ConfigTestData.AUTH_CONFIG;
import static de.bdr.pidp.issuer.authorization.config.MetaTestData.AUTH_METADATA;
import static de.bdr.pidp.issuer.base.PidDataConst.DPOP_NONCE_HEADER;
import static de.bdr.pidp.issuer.testdata.TestUtils.ATTESTED_KEYS;
import static de.bdr.pidp.issuer.testdata.TestUtils.DEVICE_JWK_THUMBPRINT;
import static de.bdr.pidp.issuer.testdata.TestUtils.DEVICE_KEY_PAIR;
import static de.bdr.pidp.issuer.testdata.TestUtils.DEVICE_PUBLIC_KEY;
import static de.bdr.pidp.issuer.testdata.TestUtils.KEY_ATTESTATION_TRUST_ANCHOR;
import static de.bdr.pidp.issuer.testdata.TestUtils.KEY_ATTESTATION_TRUST_ANCHORS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.InstanceOfAssertFactories.type;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DPoPValidatorTest {
    private static final HttpMethod METHOD = HttpMethod.POST;
    private static final UUID KEY_ATTESTATION_DISABLED_CLIENT_ID = UUID.randomUUID();
    private static final DPoPNonceService nonceService = mock(DPoPNonceService.class);
    private static final ClientConfigurationService clientConfigurationService = mock(ClientConfigurationService.class);
    @Spy
    private DPoPKeyAttestationVerifier keyAttestationVerifier = new DPoPKeyAttestationVerifier(AUTH_CONFIG, AUTH_METADATA);

    private DPoPValidator dPoPValidator;

    @BeforeAll
    void setUp() {
        doReturn(Set.of(KEY_ATTESTATION_DISABLED_CLIENT_ID.toString())).when(clientConfigurationService).getDisabledKeyAttestationClientsForTokenRequest();

        dPoPValidator = new DPoPValidator(AUTH_CONFIG, AUTH_METADATA, nonceService, clientConfigurationService, keyAttestationVerifier);
    }

    @Test
    @DisplayName("Verify DPoP validation")
    void test001a() {
        UUID clientId = UUID.randomUUID();
        var nonce = prepareNonce();
        var session = new AuthSession(TestUtils.randomSessionId());
        session.setDPoPNonce(nonce);
        var dPoPProof = prepareDPoPProof(nonce);

        doReturn(nonce).when(nonceService).fetchFromAuthSession(any());
        doReturn(KEY_ATTESTATION_TRUST_ANCHOR).when(clientConfigurationService).getKeyAttestationCerts(clientId);

        var jwkThumbprintConfirmation = dPoPValidator.validateDPoPProof(dPoPProof, session, true, clientId.toString());
        assertThat(jwkThumbprintConfirmation.getValue()).isEqualTo(DEVICE_JWK_THUMBPRINT);
    }

    @Test
    @DisplayName("Verify DPoP validation with several key attestation trust anchors")
    void test001b() {
        UUID clientId = UUID.randomUUID();
        var nonce = prepareNonce();
        var session = new AuthSession(TestUtils.randomSessionId());
        session.setDPoPNonce(nonce);
        var dPoPProof = prepareDPoPProof(nonce);

        doReturn(nonce).when(nonceService).fetchFromAuthSession(any());
        doReturn(KEY_ATTESTATION_TRUST_ANCHORS).when(clientConfigurationService).getKeyAttestationCerts(clientId);

        var jwkThumbprintConfirmation = dPoPValidator.validateDPoPProof(dPoPProof, session, true, clientId.toString());
        assertThat(jwkThumbprintConfirmation.getValue()).isEqualTo(DEVICE_JWK_THUMBPRINT);
    }

    @ParameterizedTest
    @DisplayName("Verify exception when DPoP header not present")
    @NullAndEmptySource
    void test002(List<String> dpopHeaders) {
        var session = new AuthSession(TestUtils.randomSessionId());

        assertThatThrownBy(() -> dPoPValidator.validateDPoPProof(dpopHeaders, session, true, UUID.randomUUID().toString()))
            .hasMessage("DPoP header missing")
            .asInstanceOf(type(DPoPValidationException.class))
            .extracting(OAuthException::getErrorCode).isEqualTo("invalid_dpop_proof");
    }

    @Test
    @DisplayName("Verify exception when DPoP invalid")
    void test003() {
        var session = new AuthSession(TestUtils.randomSessionId());
        var nonce = prepareNonce();
        doReturn(nonce).when(nonceService).provideAndSave(any());
        var dPoPProof = prepareDPoPProofWithoutNonce();

        assertThatThrownBy(() -> dPoPValidator.validateDPoPProof(dPoPProof, session, true, UUID.randomUUID().toString()))
            .hasMessage("Use of DPoP nonce required")
            .asInstanceOf(type(DPoPValidationException.class))
            .extracting(OAuthException::getErrorCode, e -> e.getHeader().get(DPOP_NONCE_HEADER))
            .containsExactly("use_dpop_nonce", nonce.nonce());
    }

    @Test
    @DisplayName("Verify exception when DPoP nonce expired")
    void test004() {
        var session = new AuthSession(TestUtils.randomSessionId());
        var nonce = new Nonce(RandomUtil.randomString(), Instant.now().minusSeconds(70));
        doReturn(nonce).when(nonceService).fetchFromAuthSession(any());
        var dPoPProof = prepareDPoPProof(nonce);

        assertThatThrownBy(() -> dPoPValidator.validateDPoPProof(dPoPProof, session, true, UUID.randomUUID().toString()))
            .hasMessage("DPoP nonce is expired")
            .asInstanceOf(type(DPoPValidationException.class))
            .extracting(OAuthException::getErrorCode).isEqualTo("invalid_dpop_proof");
    }

    @Test
    @DisplayName("Verify exception when DPoP nonce is invalid")
    void test005() {
        var session = new AuthSession(TestUtils.randomSessionId());
        doReturn(prepareNonce()).when(nonceService).fetchFromAuthSession(any());
        var dPoPProof = prepareDPoPProof(prepareNonce());

        assertThatThrownBy(() -> dPoPValidator.validateDPoPProof(dPoPProof, session, true, UUID.randomUUID().toString()))
            .hasMessageStartingWith("Invalid DPoP proof")
            .asInstanceOf(type(DPoPValidationException.class))
            .extracting(OAuthException::getErrorCode).isEqualTo("invalid_dpop_proof");
    }

    @Test
    @DisplayName("Verify exception when key attestation missing")
    void test007() {
        var session = new AuthSession(TestUtils.randomSessionId());
        var nonce = prepareNonce();
        doReturn(nonce).when(nonceService).fetchFromAuthSession(any());
        doReturn(nonce).when(nonceService).provideAndSave(session);
        session.setDPoPNonce(nonce);

        var dPoPProof = prepareDPoPProofWithoutKeyAttestation(nonce);

        assertThatThrownBy(() -> dPoPValidator.validateDPoPProof(dPoPProof, session, true, UUID.randomUUID().toString()))
            .hasMessage("key_attestation is missing.")
            .asInstanceOf(type(DPoPValidationException.class))
            .extracting(OAuthException::getErrorCode).isEqualTo("invalid_dpop_proof");
    }

    @Test
    @DisplayName("Verify exception when key attestation with more than one attested key")
    void test008() {
        var session = new AuthSession(TestUtils.randomSessionId());
        UUID clientId = UUID.randomUUID();
        var nonce = prepareNonce();
        var keyAttestationJwt = TestUtils.getKeyAttestationJwtForDPoP(nonce.nonce(), List.of(DEVICE_PUBLIC_KEY, DEVICE_PUBLIC_KEY));
        doReturn(nonce).when(nonceService).fetchFromAuthSession(any());
        session.setDPoPNonce(nonce);

        doReturn(KEY_ATTESTATION_TRUST_ANCHOR).when(clientConfigurationService).getKeyAttestationCerts(clientId);
        var dPopProof = prepareDPoPProof(nonce, keyAttestationJwt);

        assertThatThrownBy(() -> dPoPValidator.validateDPoPProof(dPopProof, session, true, clientId.toString()))
            .hasMessage("attested_keys does not contains exactly one key.")
            .asInstanceOf(type(DPoPValidationException.class))
            .extracting(OAuthException::getErrorCode).isEqualTo("invalid_dpop_proof");
    }

    @Test
    @DisplayName("Verify exception when key attestation with attested key different from dpop.jwk")
    void test009() {
        var session = new AuthSession(TestUtils.randomSessionId());
        UUID clientId = UUID.randomUUID();
        var nonce = prepareNonce();
        var keyAttestationJwt = TestUtils.getKeyAttestationJwtForDPoP(nonce.nonce(), ATTESTED_KEYS);
        doReturn(nonce).when(nonceService).fetchFromAuthSession(any());
        session.setDPoPNonce(nonce);

        doReturn(KEY_ATTESTATION_TRUST_ANCHOR).when(clientConfigurationService).getKeyAttestationCerts(clientId);
        var dPoPProof = prepareDPoPProof(nonce, keyAttestationJwt);

        assertThatThrownBy(() -> dPoPValidator.validateDPoPProof(dPoPProof, session, true, clientId.toString()))
            .hasMessage("attested key is not equals to DPoP JWK.")
            .asInstanceOf(type(DPoPValidationException.class))
            .extracting(OAuthException::getErrorCode).isEqualTo("invalid_dpop_proof");
    }

    @Test
    @DisplayName("Verify DPoP validation is successful with additional property at DPoP key as compared to the attested key")
    void test010() throws ParseException, JOSEException {
        var session = new AuthSession(TestUtils.randomSessionId());
        UUID clientId = UUID.randomUUID();
        var nonce = prepareNonce();
        doReturn(nonce).when(nonceService).fetchFromAuthSession(any());
        session.setDPoPNonce(nonce);
        doReturn(KEY_ATTESTATION_TRUST_ANCHOR).when(clientConfigurationService).getKeyAttestationCerts(clientId);

        // add a property to the used DPoP key, the attested keys contain the original device public key
        Map<String, Object> jsonObject1 = DEVICE_KEY_PAIR.toJSONObject();
        jsonObject1.put("x5u", "http://localhost:8080");
        ECKey deviceKeyPairWithAdditionalProperty = ECKey.parse(jsonObject1);

        assertThat(DEVICE_KEY_PAIR.toPublicJWK())
            .isNotEqualTo(deviceKeyPairWithAdditionalProperty.toPublicJWK());
        assertThat(DEVICE_KEY_PAIR.toPublicJWK().computeThumbprint())
            .isEqualTo(deviceKeyPairWithAdditionalProperty.toPublicJWK().computeThumbprint());

        var dPoPProof = prepareDPoPProofWithDPoPDeviceKeyPair(deviceKeyPairWithAdditionalProperty, nonce);

        var jwkThumbprintConfirmation = dPoPValidator.validateDPoPProof(dPoPProof, session, true, clientId.toString());
        assertThat(jwkThumbprintConfirmation.getValue()).isEqualTo(DEVICE_JWK_THUMBPRINT);
    }

    @Test
    @DisplayName("Verify DPoP validation when key attestation missing, but client is at disabled list")
    void test011() {
        var nonce = prepareNonce();
        var session = new AuthSession(TestUtils.randomSessionId());
        session.setDPoPNonce(nonce);
        var dPoPProof = prepareDPoPProofWithoutKeyAttestation(nonce);

        doReturn(nonce).when(nonceService).fetchFromAuthSession(any());
        doReturn(KEY_ATTESTATION_TRUST_ANCHOR).when(clientConfigurationService).getKeyAttestationCerts(KEY_ATTESTATION_DISABLED_CLIENT_ID);

        var jwkThumbprintConfirmation = dPoPValidator.validateDPoPProof(dPoPProof, session, true, KEY_ATTESTATION_DISABLED_CLIENT_ID.toString());
        assertThat(jwkThumbprintConfirmation.getValue()).isEqualTo(DEVICE_JWK_THUMBPRINT);
    }

    private List<String> prepareDPoPProof(@Nullable Nonce nonce, @Nullable SignedJWT keyAttestationJwt) {
        var dpopNonce = nonce == null ? null : new com.nimbusds.openid.connect.sdk.Nonce(nonce.nonce());
        var dpopJwt = keyAttestationJwt == null ?
            TestUtils.getDPoPProof(METHOD, AUTH_METADATA.getTokenEndpointURI(), dpopNonce) :
            TestUtils.getDPoPProof(METHOD, AUTH_METADATA.getTokenEndpointURI(), dpopNonce, keyAttestationJwt);
        return List.of(dpopJwt.serialize());
    }

    private List<String> prepareDPoPProof(ECKey deviceKeyPair, Nonce nonce, SignedJWT keyAttestationJwt) {
        var dpopJwt = TestUtils.getDPoPProof(deviceKeyPair, METHOD, AUTH_METADATA.getTokenEndpointURI(), new com.nimbusds.openid.connect.sdk.Nonce(nonce.nonce()), keyAttestationJwt);
        return List.of(dpopJwt.serialize());
    }

    private List<String> prepareDPoPProof(@Nullable Nonce nonce) {
        var keyAttestationJwt = TestUtils.getValidKeyAttestationJwtForDPoP(nonce == null ? null : nonce.nonce());
        return prepareDPoPProof(nonce, keyAttestationJwt);
    }

    private List<String> prepareDPoPProofWithDPoPDeviceKeyPair(ECKey deviceKeyPair, Nonce nonce) {
        var keyAttestationJwt = TestUtils.getValidKeyAttestationJwtForDPoP(nonce.nonce());
        return prepareDPoPProof(deviceKeyPair, nonce, keyAttestationJwt);
    }

    private List<String> prepareDPoPProofWithoutKeyAttestation(Nonce nonce) {
        return prepareDPoPProof(nonce, null);
    }

    private List<String> prepareDPoPProofWithoutNonce() {
        return prepareDPoPProof(null);
    }

    private Nonce prepareNonce() {
        return new Nonce(RandomUtil.randomString(), Duration.ofSeconds(30));
    }

}
