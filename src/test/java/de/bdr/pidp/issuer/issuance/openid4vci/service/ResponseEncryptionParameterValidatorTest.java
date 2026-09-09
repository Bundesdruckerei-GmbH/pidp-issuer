/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import de.bdr.pidp.issuer.issuance.config.IssuanceTestMetadata;
import de.bdr.pidp.issuer.issuance.openid4vci.exception.InvalidEncryptionParametersException;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.junit.jupiter.api.Test;

import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ResponseEncryptionParameterValidatorTest {

    public static final EncryptionMethod SUPPORTED_ENCRYPTION_METHOD = EncryptionMethod.A256GCM;
    private final ResponseEncryptionParameterValidator subject = new ResponseEncryptionParameterValidator(IssuanceTestMetadata.ISSUANCE_METADATA);

    @Test
    void shouldVerifySuccessfully() {
        var jwk = TestUtils.generateECDHEncryptionKey();

        var alg = subject.validate(jwk, SUPPORTED_ENCRYPTION_METHOD);

        var expectedAlg = Objects.requireNonNull(jwk.getAlgorithm());
        assertThat(alg).isEqualTo(expectedAlg);
    }

    @Test
    void shouldFailOnUnsupportedAlg() {
        var jwk = TestUtils.generateEcKey();

        assertThatThrownBy(() -> subject.validate(jwk, SUPPORTED_ENCRYPTION_METHOD))
            .isInstanceOf(InvalidEncryptionParametersException.class)
            .hasMessage("Unsupported response encryption JWE algorithm in provided response encryption JWK");
    }

    @Test
    void shouldFailOnMissingAlg() throws JOSEException {
        var jwk = new ECKeyGenerator(Curve.P_256).generate();

        assertThatThrownBy(() -> subject.validate(jwk, SUPPORTED_ENCRYPTION_METHOD))
            .isInstanceOf(InvalidEncryptionParametersException.class)
            .hasMessage("Missing response encryption JWE algorithm in provided JWK");
    }

    @Test
    void shouldFailOnUnsupportedEncryptionMethod() {
        var jwk = TestUtils.generateECDHEncryptionKey();
        var enc = EncryptionMethod.A128GCM;

        assertThatThrownBy(() -> subject.validate(jwk, enc))
            .isInstanceOf(InvalidEncryptionParametersException.class)
            .hasMessage("Unsupported response encryption method");
    }
}
