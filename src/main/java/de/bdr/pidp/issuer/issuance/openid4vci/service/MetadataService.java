/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.jwk.JWKUtils;
import de.bdr.pidp.issuer.issuance.core.signer.CredentialSigner;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;

@Service
public class MetadataService {

    private final CredentialSigner credentialSigner;

    public MetadataService(CredentialSigner credentialSigner) {
        this.credentialSigner = credentialSigner;
    }

    public Collection<JWK> getJWKs() {
        return Collections.singleton(getJWK());
    }

    private JWK getJWK() {
        var leafCert = credentialSigner.getCertificateChain().getFirst();
        try {
            var jwk = JWK.parse(leafCert);
            return JWKUtils.extendWithKeyID(jwk, kid(leafCert));
        } catch (CertificateEncodingException | IOException | JOSEException e) {
            throw new PidServerException("Could not parse JWK from certificate", e);
        }
    }

    private static String kid(X509Certificate first) throws CertificateEncodingException, IOException {
        Certificate cert = Certificate.getInstance(first.getEncoded());
        return Base64.getEncoder()
            .encodeToString(new IssuerSerial(cert.getIssuer(), cert.getSerialNumber().getValue()).getEncoded());
    }
}
