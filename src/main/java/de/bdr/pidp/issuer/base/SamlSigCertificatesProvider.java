/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

@Component
@RequiredArgsConstructor
public class SamlSigCertificatesProvider {

    private static final Set<String> PRINCIPAL_PART_NOT_PROD = Set.of("ref", "test");
    private static final Set<String> SERVER_PART_NOT_PROD = Set.of("ref", "localhost");

    @Value("${pidi.log-request-response}")
    private String logRequestResponse;

    @Value("${pidi.identification.server.url}")
    private String serverUrl;

    @Value("${pidi.identification.server.certificate-sig-paths}")
    private String[] serverCertificateSigPaths;

    private final FileResourceHelper fileResourceHelper;

    @Getter
    private List<X509Certificate> samlSignatureCertificates;

    @PostConstruct
    protected void readCertificatesAndCheckConfiguration() {
        samlSignatureCertificates = Arrays.stream(serverCertificateSigPaths).map(fileResourceHelper::readCertificate).toList();

        // If there is at least one certificate that does not meet the criteria for a test certificate,
        // then we are in a productive environment.
        val principalIsInProd = new AtomicBoolean(false);
        samlSignatureCertificates.forEach(certificate -> {
            String name = certificate.getSubjectX500Principal().getName().toLowerCase();
            if (PRINCIPAL_PART_NOT_PROD.stream().noneMatch(name::contains)) {
                principalIsInProd.set(true);
            }
        });

        // If the server URL does not meet the criteria for a test URL, then we are in a productive environment.
        val serverIsInProd = new AtomicBoolean(false);
        String server = serverUrl.toLowerCase();
        if (SERVER_PART_NOT_PROD.stream().noneMatch(server::contains)) {
            serverIsInProd.set(true);
        }
        if (serverIsInProd.get() ^ principalIsInProd.get()) {
            throw new PidServerException("Found illegal configuration for eID signature certificates and server url!");
        }
        if (principalIsInProd.get() && "true".equals(logRequestResponse)) {
            throw new PidServerException("Found illegal configuration for logging!");
        }
    }
}
