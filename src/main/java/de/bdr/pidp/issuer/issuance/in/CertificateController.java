/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.in;

import de.bdr.pidp.issuer.issuance.core.service.CertificateProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("certificates")
@RequiredArgsConstructor
public class CertificateController {

    private final CertificateProvider certificateProvider;

    @GetMapping(path = "root-ca.crt", produces = MediaType.TEXT_PLAIN_VALUE)
    String getRootCaCertificate() {
        return certificateProvider.rootCaCertificatePEM();
    }

    @GetMapping(path = "access.crt", produces = MediaType.TEXT_PLAIN_VALUE)
    String getAccessCertificate() {
        return certificateProvider.accessCertificatePEM();
    }
}
