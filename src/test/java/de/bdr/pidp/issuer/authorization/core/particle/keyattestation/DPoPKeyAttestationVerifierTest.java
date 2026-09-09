/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.particle.keyattestation;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import de.bdr.pidp.issuer.authorization.ConfigTestData;
import de.bdr.pidp.issuer.authorization.core.exception.DPoPValidationException;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DPoPKeyAttestationVerifierTest {

    private final Set<X509Certificate> rootCerts = TestUtils.KEY_ATTESTATION_TRUST_ANCHOR;
    private final DPoPKeyAttestationVerifier verifier = new DPoPKeyAttestationVerifier(
            Set.of(JWSAlgorithm.ES256),
            List.of("iso_18045_high"),
            List.of("iso_18045_high"),
            ConfigTestData.AUTH_CONFIG.allowSelfSignedAttestationCert(),
            ConfigTestData.AUTH_CONFIG.getProofTimeTolerance()
    );

    @ParameterizedTest
    @ValueSource(strings = {"nonce"})
    @NullAndEmptySource
    void successWithAnyDpopNonce(String nonce) {
        var attestation = TestUtils.getValidKeyAttestationJwtForDPoP(nonce);
        var attestedKeys = verifier.verify(attestation, rootCerts);

        assertThat(attestedKeys).containsAll(TestUtils.ATTESTED_KEYS_DPOP);
    }

    @Test
    void invalidJOSEObjectTypeDpopAttestation() {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults("nonce").build();
        var attestation = TestUtils.getKeyAttestationJwt(claims, JOSEObjectType.JWT);

        assertThatThrownBy(() -> verifier.verify(attestation, rootCerts))
                .isInstanceOf(DPoPValidationException.class)
                .hasMessage("Key attestation JWT invalid: JOSE header typ (type) JWT not allowed");
    }

    @Test
    void dpopAttestationWithoutAttestedKeys() {
        var attestation = TestUtils.getKeyAttestationJwtForDPoP("nonce", Collections.emptyList());

        assertThatThrownBy(() -> verifier.verify(attestation, rootCerts))
                .isInstanceOf(DPoPValidationException.class);
    }

    @Test
    void missingX5CHeader() {
        var claims = TestUtils.getKeyAttestationClaimsBuilderWithDefaults("nonce").build();
        var attestation = TestUtils.buildJWT(claims, TestUtils.KEY_ATTESTATION_TYPE, TestUtils.generateEcKey());

        assertThatThrownBy(() -> verifier.verify(attestation, rootCerts))
            .isInstanceOf(DPoPValidationException.class)
            .hasMessage("Key attestation JWT invalid: Missing JOSE X.509 certificate chain (x5c) header");
    }
}
