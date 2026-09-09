/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service.dpop;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.base.RandomUtil;
import de.bdr.pidp.issuer.issuance.openid4vci.out.authorization.AuthorizationDiscoveryAdapter;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.http.HttpMethod;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static de.bdr.pidp.issuer.issuance.ConfigTestData.ISSUANCE_CONFIG;
import static de.bdr.pidp.issuer.issuance.config.IssuanceTestMetadata.ISSUANCE_METADATA;
import static de.bdr.pidp.issuer.testdata.TestAccessTokenIssuer.buildAccessToken;
import static de.bdr.pidp.issuer.testdata.TestUtils.DEVICE_JWK_THUMBPRINT;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.InstanceOfAssertFactories.type;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CredentialRequestDPoPValidatorTest {
    private static final HttpMethod METHOD = HttpMethod.POST;
    private final AuthorizationDiscoveryAdapter authorizationDiscoveryAdapter = mock(AuthorizationDiscoveryAdapter.class);
    private CredentialRequestDPoPValidator credentialRequestDPoPValidator;

    @BeforeAll
    void setUpMocks() {
        when(authorizationDiscoveryAdapter.getDPoPSigningAlgorithms())
            .thenReturn(JWSAlgorithm.Family.EC.stream().toList());

        credentialRequestDPoPValidator = new CredentialRequestDPoPValidator(ISSUANCE_CONFIG, ISSUANCE_METADATA,
            authorizationDiscoveryAdapter);
    }

    @Test
    @DisplayName("Verify DPoP validation is successful")
    void test001() {
        var nonce = prepareNonce();
        SignedJWT accessTokenJWT = buildAccessToken();
        var dpopJwt = TestUtils.getDPoPProof(METHOD, ISSUANCE_METADATA.credentialEndpoint(), new DPoPAccessToken(accessTokenJWT.serialize()), com.nimbusds.openid.connect.sdk.Nonce.parse(nonce.nonce()));

        assertDoesNotThrow(() -> credentialRequestDPoPValidator.validateResourceRequestDPoPProof(accessTokenJWT, List.of(dpopJwt.serialize()), METHOD.name(), nonce, new JWKThumbprintConfirmation(DEVICE_JWK_THUMBPRINT)));
    }

    @Test
    @DisplayName("Verify exception when DPoP header not present")
    void test002() {
        SignedJWT accessTokenJWT = buildAccessToken();
        var nonce = prepareNonce();

        assertThatThrownBy(() -> credentialRequestDPoPValidator.validateResourceRequestDPoPProof(accessTokenJWT, null, METHOD.name(), nonce, new JWKThumbprintConfirmation(DEVICE_JWK_THUMBPRINT)))
            .hasMessage("DPoP header missing")
            .asInstanceOf(type(IssuanceDPoPValidationException.class))
            .extracting(e -> e.getError().getCode()).isEqualTo("invalid_dpop_proof");
    }

    @Test
    @DisplayName("Verify exception when DPoP invalid")
    void test003() {
        Nonce nonce = new Nonce(null, Duration.ofSeconds(30));
        SignedJWT accessTokenJWT = buildAccessToken();
        var dpopJwt = TestUtils.getDPoPProof(METHOD, ISSUANCE_METADATA.credentialEndpoint(), new DPoPAccessToken(accessTokenJWT.serialize()), com.nimbusds.openid.connect.sdk.Nonce.parse(nonce.nonce()));

        assertThatThrownBy(() -> credentialRequestDPoPValidator.validateResourceRequestDPoPProof(accessTokenJWT, List.of(dpopJwt.serialize()), METHOD.name(), nonce, new JWKThumbprintConfirmation(DEVICE_JWK_THUMBPRINT)))
            .asInstanceOf(type(MissingDPoPNonceException.class))
            .extracting(MissingDPoPNonceException::getAcceptedAlgs).isNotNull();
    }

    @Test
    @DisplayName("Verify exception when DPoP nonce expired")
    void test004() {
        var nonce = new Nonce(RandomUtil.randomString(),
            Instant.now().minusSeconds(70)); // > proofTimeTolerance
        SignedJWT accessTokenJWT = buildAccessToken();
        var dpopJwt = TestUtils.getDPoPProof(METHOD, ISSUANCE_METADATA.credentialEndpoint(), new DPoPAccessToken(accessTokenJWT.serialize()), com.nimbusds.openid.connect.sdk.Nonce.parse(nonce.nonce()));

        assertThatThrownBy(() -> credentialRequestDPoPValidator.validateResourceRequestDPoPProof(accessTokenJWT, List.of(dpopJwt.serialize()), METHOD.name(), nonce, new JWKThumbprintConfirmation(DEVICE_JWK_THUMBPRINT)))
            .hasMessage("DPoP nonce is expired")
            .asInstanceOf(type(IssuanceDPoPValidationException.class))
            .extracting(e -> e.getError().getCode()).isEqualTo("invalid_dpop_proof");
    }

    @Test
    @DisplayName("Verify exception when DPoP nonce is invalid")
    void test005() {
        SignedJWT accessTokenJWT = buildAccessToken();
        var dpopJwt = TestUtils.getDPoPProof(METHOD, ISSUANCE_METADATA.credentialEndpoint(), new DPoPAccessToken(accessTokenJWT.serialize()), com.nimbusds.openid.connect.sdk.Nonce.parse(prepareNonce().nonce()));
        var nonce = prepareNonce(); // not the same nonce used in the DPoP JWT

        assertThatThrownBy(() -> credentialRequestDPoPValidator.validateResourceRequestDPoPProof(accessTokenJWT, List.of(dpopJwt.serialize()), METHOD.name(), nonce, new JWKThumbprintConfirmation(DEVICE_JWK_THUMBPRINT)))
            .hasMessageStartingWith("Invalid DPoP proof")
            .asInstanceOf(type(IssuanceDPoPValidationException.class))
            .extracting(e -> e.getError().getCode())
            .isEqualTo("invalid_dpop_proof");
    }

    private Nonce prepareNonce() {
        return new Nonce(RandomUtil.randomString(), Duration.ofSeconds(30));
    }
}
