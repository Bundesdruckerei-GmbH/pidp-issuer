/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwt;

import de.bdr.pidp.issuer.testdata.TestUtils;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Isolated;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.security.cert.CertPathValidatorException;
import java.security.cert.PKIXReason;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(OutputCaptureExtension.class)
@Isolated
class X509ValidatorTest {

    private final X509Validator validator = new X509Validator(true);
    private final X509Validator validatorNoSelfSigned = new X509Validator(false);

    @Test
    void validateSelfSignedClientCertificate() {
        var anchorCert = TestUtils.CLIENT_ATTESTATION_TRUST_ANCHOR_SELF_SIGNED;

        assertThatNoException()
            .isThrownBy(() -> validator.validate(anchorCert, TestUtils.CLIENT_CERTIFICATE_SELF_SIGNED));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/certificates/wallet-wia-demo.crt", "/certificates/wallet-wte-demo.crt"})
    void validateWalletClientCertificateChain(String clientCerts) {
        var anchorCerts = TestUtils.readClientCertificate("/certificates/nw-root-ca.pem");
        var chain = TestUtils.readClientCertificate(clientCerts);

        assertThatNoException()
            .isThrownBy(() -> validatorNoSelfSigned.validate(Set.of(anchorCerts.getFirst()), chain));
    }

    @Test
    void validateSelfSignedClientCertificateWhenSelfSignedNotAllowed(CapturedOutput output) {
        var anchorCert = TestUtils.CLIENT_ATTESTATION_TRUST_ANCHOR_SELF_SIGNED;

        assertThatThrownBy(() -> validatorNoSelfSigned.validate(anchorCert, TestUtils.CLIENT_CERTIFICATE_SELF_SIGNED))
            .asInstanceOf(InstanceOfAssertFactories.type(CertPathValidatorException.class))
            .extracting(CertPathValidatorException::getReason).isEqualTo(X509Validator.ValidationExceptionReason.SELF_SIGNED);
        assertThat(output.getOut()).contains("logType=security", "untrusted certificate, reason: SELF_SIGNED");
    }

    @Test
    void validateSelfSignedClientCertificateWithListOfAnchorCerts() {
        var anchorCerts = TestUtils.CLIENT_ATTESTATION_TRUST_ANCHORS;

        assertThatNoException()
            .isThrownBy(() -> validator.validate(anchorCerts, TestUtils.CLIENT_CERTIFICATE_SELF_SIGNED));
    }

    @Test
    void validateSelfSignedClientCertificateWithListOfAnchorCertsWhenSelfSignedNotAllowed(CapturedOutput output) {
        var anchorCerts = TestUtils.CLIENT_ATTESTATION_TRUST_ANCHORS;

        assertThatThrownBy(() -> validatorNoSelfSigned.validate(anchorCerts, TestUtils.CLIENT_CERTIFICATE_SELF_SIGNED))
            .asInstanceOf(InstanceOfAssertFactories.type(CertPathValidatorException.class))
            .extracting(CertPathValidatorException::getReason).isEqualTo(X509Validator.ValidationExceptionReason.SELF_SIGNED);
        assertThat(output.getOut()).contains("logType=security", "untrusted certificate, reason: SELF_SIGNED");
    }

    @Test
    void validateCertificateChainWithTrustAnchorCA(CapturedOutput output) {
        var anchorCert = TestUtils.CLIENT_ATTESTATION_TRUST_ANCHOR_CHAIN_CA;

        assertThatThrownBy(() -> validatorNoSelfSigned.validate(anchorCert, TestUtils.CLIENT_CERTIFICATE_CHAIN))
            .asInstanceOf(InstanceOfAssertFactories.type(CertPathValidatorException.class))
            .extracting(CertPathValidatorException::getReason).isEqualTo(X509Validator.ValidationExceptionReason.CHAIN_CONTAINS_TRUST_ANCHOR);
        assertThat(output.getOut()).contains("logType=security", "invalid certificate, reason: CHAIN_CONTAINS_TRUST_ANCHOR");
    }

    @Test
    void validateSubCertificate() {
        var anchorCert = TestUtils.CLIENT_ATTESTATION_TRUST_ANCHOR_CHAIN_CA;

        assertThatNoException()
                .isThrownBy(() -> validator.validate(anchorCert, TestUtils.CLIENT_SUB_CLIENT_CERTIFICATE));
    }

    @Test
    void validateSubCertificateWithListOfAnchorCerts() {
        var anchorCerts = TestUtils.CLIENT_ATTESTATION_TRUST_ANCHORS;

        assertThatNoException()
            .isThrownBy(() -> validator.validate(anchorCerts, TestUtils.CLIENT_SUB_CLIENT_CERTIFICATE));
    }

    @Test
    void validateNoAnchor(CapturedOutput output) {
        var anchorCert = TestUtils.CLIENT_ATTESTATION_TRUST_ANCHOR_CHAIN_LEAF;

        assertThatThrownBy(() -> validator.validate(anchorCert, TestUtils.CLIENT_SUB_CLIENT_CERTIFICATE))
                .asInstanceOf(InstanceOfAssertFactories.type(CertPathValidatorException.class))
                .extracting(CertPathValidatorException::getReason).isEqualTo(PKIXReason.NO_TRUST_ANCHOR);
        assertThat(output.getOut()).contains("logType=security", "untrusted certificate, reason: NO_TRUST_ANCHOR");
    }

    @Test
    void validateCertificateExpired(CapturedOutput output) {
        var anchorCert = TestUtils.CLIENT_CERTIFICATE_TEST_RSA.stream().collect(Collectors.toUnmodifiableSet());

        assertThatThrownBy(() -> validator.validate(anchorCert, TestUtils.CLIENT_EXPIRED_CLIENT_CERTIFICATE))
                .asInstanceOf(InstanceOfAssertFactories.type(CertPathValidatorException.class))
                .extracting(CertPathValidatorException::getReason).isEqualTo(CertPathValidatorException.BasicReason.EXPIRED);
        assertThat(output.getOut()).contains("logType=security", "expired certificate, reason: EXPIRED");
    }

    @Test
    void validateCertificateInvalidSignature(CapturedOutput output) {
        assertThatThrownBy(() -> validator.validate(Set.of(TestUtils.CLIENT_UNKNOWN_CERTIFICATE.getFirst()), TestUtils.CLIENT_UNKNOWN_CERTIFICATE))
                .asInstanceOf(InstanceOfAssertFactories.type(CertPathValidatorException.class))
                .extracting(CertPathValidatorException::getReason).isEqualTo(CertPathValidatorException.BasicReason.INVALID_SIGNATURE);
        assertThat(output.getOut()).contains("logType=security", "untrusted certificate, reason: INVALID_SIGNATURE");
    }

    @Test
    void validateKeyAttestationCertificate() {
        var anchorCert = TestUtils.KEY_ATTESTATION_TRUST_ANCHOR;

        assertThatNoException()
            .isThrownBy(() -> validator.validate(anchorCert, TestUtils.KEY_ATTESTATION_CERTIFICATE));
    }

    @Test
    void validateKeyAttestationWithListOfAnchorCerts() {
        var anchorCerts = TestUtils.KEY_ATTESTATION_TRUST_ANCHORS;

        assertThatNoException()
            .isThrownBy(() -> validator.validate(anchorCerts, TestUtils.KEY_ATTESTATION_CERTIFICATE));
    }

    @Test
    void validateAttestationCertificateChain(CapturedOutput output) {
        var anchorCerts = TestUtils.readClientCertificate("/certificates/pidp-test-root.crt");
        var chain = TestUtils.readClientCertificate("/certificates/pidp-missing-key-usage-in-subca.crt");


        assertThatThrownBy(() -> validator.validate(Set.of(anchorCerts.getLast()), chain))
            .asInstanceOf(InstanceOfAssertFactories.type(CertPathValidatorException.class))
            .extracting(CertPathValidatorException::getReason).isEqualTo(X509Validator.ValidationExceptionReason.MISSING_KEY_USAGE);
        assertThat(output.getOut()).contains("logType=security", "invalid certificate, reason: MISSING_KEY_USAGE");
    }

    @Test
    void validateAttestationCertificateVersion1(CapturedOutput output) {
        var chain = TestUtils.readClientCertificate("/certificates/pidp-invalid-version-1.crt");

        assertThatThrownBy(() -> validator.validate(Set.of(chain.getFirst()), chain))
            .asInstanceOf(InstanceOfAssertFactories.type(CertPathValidatorException.class))
            .extracting(CertPathValidatorException::getReason).isEqualTo(X509Validator.ValidationExceptionReason.INVALID_VERSION);
        assertThat(output.getOut()).contains("logType=security", "invalid certificate, reason: INVALID_VERSION");
    }

    @Test
    void validateAttestationCertificateInvalidCriticalExtension(CapturedOutput output) {
        var chain = TestUtils.readClientCertificate("/certificates/pidp-invalid-critical-ext.crt");

        assertThatThrownBy(() -> validator.validate(Set.of(chain.getFirst()), chain))
            .asInstanceOf(InstanceOfAssertFactories.type(CertPathValidatorException.class))
            .extracting(CertPathValidatorException::getReason).isEqualTo(X509Validator.ValidationExceptionReason.NOT_ALLOWED_CRITICAL_EXTENSION);
        assertThat(output.getOut()).contains("logType=security", "invalid certificate, reason: NOT_ALLOWED_CRITICAL_EXTENSION");
    }

    @Test
    void validateAttestationCertificatePathLen(CapturedOutput output) {
        var anchorCerts = TestUtils.readClientCertificate("/certificates/pidp-test-root.crt");
        var chain = TestUtils.readClientCertificate("/certificates/pidp-invalid-pathlen.crt");

        assertThatThrownBy(() -> validator.validate(Set.of(anchorCerts.getLast()), chain))
            .asInstanceOf(InstanceOfAssertFactories.type(CertPathValidatorException.class))
            .extracting(CertPathValidatorException::getReason).isEqualTo(PKIXReason.PATH_TOO_LONG);
        assertThat(output.getOut()).contains("logType=security", "invalid certificate, reason: PATH_TOO_LONG");
    }

    @Test
    void validateTargetCertInChainExpired(CapturedOutput output) {
        var anchorCert = TestUtils.CLIENT_ATTESTATION_TRUST_ANCHORS;
        var chain = TestUtils.readClientCertificate("/certificates/pidp-key-attestation-wte-test-expired.crt");

        assertThatThrownBy(() -> validator.validate(anchorCert, chain))
            .asInstanceOf(InstanceOfAssertFactories.type(CertPathValidatorException.class))
            .extracting(CertPathValidatorException::getReason).isEqualTo(CertPathValidatorException.BasicReason.EXPIRED);
        assertThat(output.getOut()).contains("logType=security", "expired certificate, reason: EXPIRED");
    }

    @Test
    void validateSubCAInChainExpired(CapturedOutput output) {
        var anchorCert = TestUtils.CLIENT_ATTESTATION_TRUST_ANCHORS;
        var chain = TestUtils.readClientCertificate("/certificates/pidp-expired-subca.crt");

        assertThatThrownBy(() -> validator.validate(anchorCert, chain))
            .asInstanceOf(InstanceOfAssertFactories.type(CertPathValidatorException.class))
            .extracting(CertPathValidatorException::getReason).isEqualTo(CertPathValidatorException.BasicReason.EXPIRED);
        assertThat(output.getOut()).contains("logType=security", "expired certificate, reason: EXPIRED");
    }
}
