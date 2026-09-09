/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.service;

import de.bdr.pidp.issuer.issuance.core.signer.CredentialSigner;
import de.bdr.pidp.issuer.issuance.core.signer.MetadataSigner;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.StringWriter;
import java.security.cert.Certificate;

@NullMarked
@Component
public class CertificateProvider {

    private final String rootCaCertificate;
    private final String accessCertificate; // for signed metadata

    public CertificateProvider(CredentialSigner credentialSigner, MetadataSigner metadataSigner) throws IOException {
        var certs = credentialSigner.getCertificateChain();
        this.rootCaCertificate = toPEM(certs.getLast());
        this.accessCertificate = toPEM(metadataSigner.getAccessCertificate());
    }

    public String rootCaCertificatePEM() {
        return rootCaCertificate;
    }

    public String accessCertificatePEM() {
        return accessCertificate;
    }

    private String toPEM(Certificate cert) throws IOException {
        try (StringWriter strWriter = new StringWriter(); JcaPEMWriter pemWriter = new JcaPEMWriter(strWriter)) {
            pemWriter.writeObject(cert);
            pemWriter.flush();
            return strWriter.toString();
        }
    }
}
