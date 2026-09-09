/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HashingRemoteSignerTest {

    public static final byte[] SIGNING_INPUT = {4, 3, 2};
    public static final byte[] DUMMY_SIGNATURE = {1, 2, 3};

    static Stream<Arguments> supportedAlgs() {
        return Stream.of(
            Arguments.arguments(JWSAlgorithm.ES256, "SHA-256"),
            Arguments.arguments(JWSAlgorithm.ES384, "SHA-384"),
            Arguments.arguments(JWSAlgorithm.ES512, "SHA-512")
        );
    }

    @ParameterizedTest
    @MethodSource("supportedAlgs")
    void signSuccess(JWSAlgorithm alg, String hashAlg) throws JOSEException, NoSuchAlgorithmException {
        AtomicReference<byte[]> capturedHash = new AtomicReference<>();
        var signer = new HashingRemoteSigner(Set.of(alg), hash -> {
            capturedHash.set(hash);
            return DUMMY_SIGNATURE;
        });

        var jwsHeader = new JWSHeader(alg);
        var signed = signer.sign(jwsHeader, SIGNING_INPUT);

        assertThat(signed.decode()).isEqualTo(DUMMY_SIGNATURE);
        var expectedHash = MessageDigest.getInstance(hashAlg).digest(SIGNING_INPUT);
        assertThat(capturedHash).hasValue(expectedHash);
    }

    @Test
    void unsupportedAlgBySigner() {
        var containingUnsupported = Set.of(JWSAlgorithm.ES256, JWSAlgorithm.EdDSA);
        assertThatThrownBy(() -> new HashingRemoteSigner(containingUnsupported, b -> b))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void unsupportedAlgByJWS() {
        var signer = new HashingRemoteSigner(Set.of(JWSAlgorithm.ES256), b -> b);

        var jwsHeader = new JWSHeader(JWSAlgorithm.RS256);

        assertThatThrownBy(() -> signer.sign(jwsHeader, SIGNING_INPUT))
            .isInstanceOf(JOSEException.class);
    }
}
