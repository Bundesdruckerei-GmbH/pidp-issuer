/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.function.Function;
import java.util.function.UnaryOperator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RemoteSignerTest {

    public static final byte[] SIGNING_INPUT = {4, 3, 2};
    public static final byte[] DUMMY_SIGNATURE = {1, 2, 3};
    public static final Base64URL DUMMY_SIGNATURE_B64 = Base64URL.encode(DUMMY_SIGNATURE);

    @Test
    void signSuccessB64() throws JOSEException {
        Function<byte[], Base64URL> fun = sigInput -> {
            assertThat(sigInput).isEqualTo(SIGNING_INPUT);
            return DUMMY_SIGNATURE_B64;
        };
        var signer = new RemoteSigner(Set.of(JWSAlgorithm.ES256), fun);

        var jwsHeader = new JWSHeader(JWSAlgorithm.ES256);
        var signed = signer.sign(jwsHeader, SIGNING_INPUT);

        assertThat(signed).isEqualTo(DUMMY_SIGNATURE_B64);
    }

    @Test
    void signSuccessByteArray() throws JOSEException {
        UnaryOperator<byte[]> fun = sigInput -> {
            assertThat(sigInput).isEqualTo(SIGNING_INPUT);
            return DUMMY_SIGNATURE;
        };
        var signer = new RemoteSigner(Set.of(JWSAlgorithm.ES256), fun);

        var jwsHeader = new JWSHeader(JWSAlgorithm.ES256);
        var signed = signer.sign(jwsHeader, SIGNING_INPUT);

        assertThat(signed.decode()).isEqualTo(DUMMY_SIGNATURE);
    }

    @Test
    void unsupportedAlgByJWS() {
        var signer = new HashingRemoteSigner(Set.of(JWSAlgorithm.ES256), b -> b);

        var jwsHeader = new JWSHeader(JWSAlgorithm.RS256);

        assertThatThrownBy(() -> signer.sign(jwsHeader, SIGNING_INPUT))
            .isInstanceOf(JOSEException.class);
    }
}
