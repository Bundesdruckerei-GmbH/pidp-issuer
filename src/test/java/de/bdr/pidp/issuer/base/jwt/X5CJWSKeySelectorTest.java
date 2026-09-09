/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.util.Base64;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

@NullMarked
class X5CJWSKeySelectorTest {

    private final X5CJWSKeySelector<X509SecurityContext> keySelector = new X5CJWSKeySelector<>(Set.of(JWSAlgorithm.RS256), true);
    private final X509SecurityContext context = () -> TestUtils.CLIENT_ATTESTATION_TRUST_ANCHOR_SELF_SIGNED;

    @Test
    void success() throws KeySourceException {
        var header = buildJWSHeader(JWSAlgorithm.RS256, TestUtils.CLIENT_CERTIFICATE_SELF_SIGNED_B64);

        var keys = keySelector.selectJWSKeys(header, context);

        var expectedPubKeys = TestUtils.CLIENT_CERTIFICATE_SELF_SIGNED.stream().map(Certificate::getPublicKey).toList();
        assertThat(keys).isEqualTo(expectedPubKeys);
    }

    @Test
    void unsupportedAlg() throws KeySourceException {
        var header = buildJWSHeader(JWSAlgorithm.PS256, TestUtils.CLIENT_CERTIFICATE_SELF_SIGNED_B64);

        var keys = keySelector.selectJWSKeys(header, context);

        assertThat(keys).isEmpty();
    }

    @Test
    void missingX5CHeader() {
        var header = buildJWSHeader(JWSAlgorithm.RS256, null);

        assertThatThrownBy(() -> keySelector.selectJWSKeys(header, context))
                .isInstanceOf(KeySourceException.class)
                .hasMessage("Missing JOSE X.509 certificate chain (x5c) header");
    }

    @Test
    void unknownCert() throws CertPathValidatorException, CertificateException {
        var x509Validator = mock(X509Validator.class);
        ReflectionTestUtils.setField(keySelector, "x509Validator", x509Validator);
        doThrow(new CertPathValidatorException()).when(x509Validator).validate(any(), any());

        var header = buildJWSHeader(JWSAlgorithm.RS256, TestUtils.CLIENT_CERTIFICATE_SELF_SIGNED_B64);

        assertThatThrownBy(() -> keySelector.selectJWSKeys(header, context))
                .isInstanceOf(KeySourceException.class)
                .hasMessageStartingWith("Invalid JOSE X.509 certificate chain (x5c) header: ");
    }

    private JWSHeader buildJWSHeader(JWSAlgorithm algorithm, @Nullable List<Base64> b64Certificates) {
        return new JWSHeader(algorithm, null, null, null, null, null, null, null, null, b64Certificates, null, true, null, null);
    }
}
