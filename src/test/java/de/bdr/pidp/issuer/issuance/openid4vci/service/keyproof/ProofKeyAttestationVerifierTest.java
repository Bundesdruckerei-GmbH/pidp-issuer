/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service.keyproof;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import de.bdr.pidp.issuer.base.RandomUtil;
import de.bdr.pidp.issuer.issuance.ConfigTestData;
import de.bdr.pidp.issuer.issuance.config.model.ProofTypeImpl;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidNonceException;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidProofException;
import de.bdr.pidp.issuer.issuance.openid4vci.service.CNonceService;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

class ProofKeyAttestationVerifierTest {

    private final CNonceService cNonceService = mock(CNonceService.class);
    private final Set<X509Certificate> rootCerts = TestUtils.KEY_ATTESTATION_TRUST_ANCHOR;
    private final ProofKeyAttestationVerifier verifier = new ProofKeyAttestationVerifier(
        cNonceService,
        Set.of(JWSAlgorithm.ES256),
        List.of("iso_18045_high"),
        List.of("iso_18045_high"),
        ConfigTestData.ISSUANCE_CONFIG.allowSelfSignedAttestationCert(),
        ConfigTestData.ISSUANCE_CONFIG.getProofTimeTolerance()
    );

    @Test
    void successWithNonceFromSession() {
        var nonce = RandomUtil.randomString();

        var attestedKeys = verifier.verify(TestUtils.getValidKeyAttestationJwt(nonce), rootCerts, List.of(nonce));

        assertThat(attestedKeys).containsAll(TestUtils.ATTESTED_KEYS);
    }

    @Test
    void successWithNonceFromService() {
        var nonce = RandomUtil.randomString();
        doReturn(true).when(cNonceService).consume(nonce);
        List<String> verifiedNonces = new ArrayList<>();

        var attestedKeys = verifier.verify(TestUtils.getValidKeyAttestationJwt(nonce), rootCerts, verifiedNonces);

        assertThat(attestedKeys).containsAll(TestUtils.ATTESTED_KEYS);
        assertThat(verifiedNonces).contains(nonce);
    }

    @Test
    void successWithKeyAttestationNotRequired() {
        var localVerifier = new ProofKeyAttestationVerifier(cNonceService, ConfigTestData.ISSUANCE_CONFIG, new ProofTypeImpl(List.of(JWSAlgorithm.ES256)));
        var nonce = RandomUtil.randomString();

        var attestedKeys = localVerifier.verify(TestUtils.getValidKeyAttestationJwt(nonce), rootCerts, List.of(nonce));

        assertThat(attestedKeys).containsAll(TestUtils.ATTESTED_KEYS);
    }

    @Test
    void emptyNonce() {
        var nonce = RandomUtil.randomString();
        doReturn(true).when(cNonceService).consume(nonce);
        List<String> verifiedNonces = new ArrayList<>();

        var attestation = TestUtils.getValidKeyAttestationJwt("");

        assertThatThrownBy(() -> verifier.verify(attestation, rootCerts, verifiedNonces))
                .isInstanceOf(InvalidNonceException.class).hasMessage("Nonce invalid: Unexpected JWT nonce (nonce) claim: ''");
    }

    @Test
    void invalidNonce() {
        var nonce = RandomUtil.randomString();
        doReturn(false).when(cNonceService).consume(nonce);
        List<String> verifiedNonces = new ArrayList<>();

        var attestation = TestUtils.getValidKeyAttestationJwt(nonce);

        assertThatThrownBy(() -> verifier.verify(attestation, rootCerts, verifiedNonces))
                .isInstanceOf(InvalidNonceException.class).hasMessage("Nonce invalid: Unexpected JWT nonce (nonce) claim: '%s'".formatted(nonce));
    }

    @Test
    void invalidJOSEObjectType() {
        var nonce = RandomUtil.randomString();
        List<String> verifiedNonces = new ArrayList<>();
        verifiedNonces.add(nonce);

        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(nonce).build();
        var attestation = TestUtils.getKeyAttestationJwt(claims, JOSEObjectType.JWT);

        assertThatThrownBy(() -> verifier.verify(attestation, rootCerts, verifiedNonces))
                .isInstanceOf(InvalidProofException.class)
                .hasMessage("Proof invalid: JOSE header typ (type) JWT not allowed");
    }

    @Test
    void missingX5CHeader() {
        var nonce = RandomUtil.randomString();
        List<String> verifiedNonces = new ArrayList<>();
        verifiedNonces.add(nonce);

        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults(nonce).build();
        var attestation = TestUtils.buildJWT(claims, TestUtils.KEY_ATTESTATION_TYPE, TestUtils.generateEcKey());

        assertThatThrownBy(() -> verifier.verify(attestation, rootCerts, verifiedNonces))
                .isInstanceOf(InvalidProofException.class)
                .hasMessage("Proof invalid: Missing JOSE X.509 certificate chain (x5c) header");
    }
}
