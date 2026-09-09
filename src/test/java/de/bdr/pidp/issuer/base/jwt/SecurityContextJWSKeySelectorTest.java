/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.jspecify.annotations.NullMarked;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@NullMarked
class SecurityContextJWSKeySelectorTest {

    private final SecurityContextJWSKeySelector<JWKSecurityContext> keySelector = new SecurityContextJWSKeySelector<>(Set.of(JWSAlgorithm.ES256));
    private final JWKSecurityContext context = () -> TestUtils.DEVICE_PUBLIC_KEY;

    @Test
    void success() throws JOSEException {
        var header = buildJWSHeader(JWSAlgorithm.ES256);

        var keys = keySelector.selectJWSKeys(header, context);

        assertThat(keys).hasSize(1).isEqualTo(List.of(TestUtils.DEVICE_PUBLIC_KEY.toECKey().toPublicKey()));
    }

    @Test
    void unsupportedAlg() throws KeySourceException {
        var header = buildJWSHeader(JWSAlgorithm.PS256);

        var keys = keySelector.selectJWSKeys(header, context);

        assertThat(keys).isEmpty();
    }

    @Test
    void emptySecurityContext() throws KeySourceException {
        var header = buildJWSHeader(JWSAlgorithm.ES256);

        var keys = keySelector.selectJWSKeys(header, () -> null);

        assertThat(keys).isEmpty();
    }

    @Test
    void JWKNotAsymmetric() throws JOSEException {
        var header = buildJWSHeader(JWSAlgorithm.ES256);
        var symmetricJwk = new OctetSequenceKeyGenerator(112).generate();

        assertThatThrownBy(() -> keySelector.selectJWSKeys(header, () -> symmetricJwk))
            .isInstanceOf(KeySourceException.class)
            .hasMessage("Invalid JWK");
    }

    private JWSHeader buildJWSHeader(JWSAlgorithm algorithm) {
        return new JWSHeader(algorithm, null, null, null, null, null, null, null, null, null, null, true, null, null);
    }
}
