/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.stream.Stream;

@ExtendWith(MockitoExtension.class)
class SamlSigCertificatesProviderTest {

    private static final String SERVER_PROD_URL = "https://dummy.eid-service.de:443";
    private static final String SERVER_TEST_URL = "http://localhost:8080";

    private static final String[] CERTS_IN_PROD = new String[]{"./src/test/resources/test_sig_prod.pem"};
    private static final String[] CERTS_IN_TEST = new String[]{"./eid/signature.pem", "./eid/alternative_signature.pem"};

    private static final String LOG_CONF_PROD = "oh_no";
    private static final String LOG_CONF_TEST = "true";

    @Spy
    private FileResourceHelper fileResourceHelper = new FileResourceHelper();

    @InjectMocks
    private SamlSigCertificatesProvider samlSigCertificatesProvider;

    @DisplayName("Happy path in test env")
    @Test
    void test001() {
        ReflectionTestUtils.setField(samlSigCertificatesProvider, "logRequestResponse", LOG_CONF_TEST);
        ReflectionTestUtils.setField(samlSigCertificatesProvider, "serverUrl", SERVER_TEST_URL);
        ReflectionTestUtils.setField(samlSigCertificatesProvider, "serverCertificateSigPaths", CERTS_IN_TEST);

        Assertions.assertThatNoException().isThrownBy(() -> samlSigCertificatesProvider.readCertificatesAndCheckConfiguration());
        Assertions.assertThat(samlSigCertificatesProvider.getSamlSignatureCertificates()).isNotEmpty();
    }

    @DisplayName("Happy path in production env")
    @Test
    void test002() {
        ReflectionTestUtils.setField(samlSigCertificatesProvider, "logRequestResponse", LOG_CONF_PROD);
        ReflectionTestUtils.setField(samlSigCertificatesProvider, "serverUrl", SERVER_PROD_URL);
        ReflectionTestUtils.setField(samlSigCertificatesProvider, "serverCertificateSigPaths", CERTS_IN_PROD);

        Assertions.assertThatNoException().isThrownBy(() -> samlSigCertificatesProvider.readCertificatesAndCheckConfiguration());
        Assertions.assertThat(samlSigCertificatesProvider.getSamlSignatureCertificates()).isNotEmpty();
    }

    @DisplayName("Misconfiguration in production env")
    @ParameterizedTest
    @MethodSource("arguments")
    void test003(String logConf, String serverUrl, String[] serverCertificateSigPaths, String errorMsg) {
        ReflectionTestUtils.setField(samlSigCertificatesProvider, "logRequestResponse", logConf);
        ReflectionTestUtils.setField(samlSigCertificatesProvider, "serverUrl", serverUrl);
        ReflectionTestUtils.setField(samlSigCertificatesProvider, "serverCertificateSigPaths", serverCertificateSigPaths);

        Assertions.assertThatExceptionOfType(PidServerException.class).isThrownBy(() -> samlSigCertificatesProvider.readCertificatesAndCheckConfiguration())
                .withMessage("Found illegal configuration for %s!".formatted(errorMsg));
    }

    private static Stream<Arguments> arguments() {
        return Stream.of(
                Arguments.arguments(LOG_CONF_TEST, SERVER_PROD_URL, CERTS_IN_PROD, "logging"),
                Arguments.arguments(LOG_CONF_PROD, SERVER_PROD_URL, CERTS_IN_TEST, "eID signature certificates and server url"),
                Arguments.arguments(LOG_CONF_PROD, SERVER_TEST_URL, CERTS_IN_PROD, "eID signature certificates and server url")
        );
    }
}
