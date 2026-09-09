/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.util.X509CertChainUtils;

import java.security.Key;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public class X5CJWSKeySelector<C extends X509SecurityContext> implements JWSKeySelector<C> {

    private final Set<JWSAlgorithm> jwsAlgorithmsSupported;
    private final X509Validator x509Validator;

    public X5CJWSKeySelector(Set<JWSAlgorithm> jwsAlgorithmsSupported, boolean allowSelfSigned) {
        this.jwsAlgorithmsSupported = jwsAlgorithmsSupported;
        x509Validator = new X509Validator(allowSelfSigned);
    }

    @Override
    public List<? extends Key> selectJWSKeys(JWSHeader header, C context) throws KeySourceException {

        if (!jwsAlgorithmsSupported.contains(header.getAlgorithm())) {
            return Collections.emptyList();
        }

        List<X509Certificate> chain;
        try {
            chain = X509CertChainUtils.parse(header.getX509CertChain());
        } catch (ParseException e) {
            throw new KeySourceException("Invalid JOSE X.509 certificate chain (x5c) header: " + e.getMessage(), e);
        }

        if (chain == null || chain.isEmpty()) {
            throw new KeySourceException("Missing JOSE X.509 certificate chain (x5c) header");
        }

        var signatureKey = chain.getFirst().getPublicKey();

        try {
            x509Validator.validate(context.getTrustAnchorCertificates(), chain);
        } catch (CertificateException | CertPathValidatorException e) {
            throw new KeySourceException("Invalid JOSE X.509 certificate chain (x5c) header: " + e.getMessage(), e);
        }

        return Collections.singletonList(signatureKey);
    }
}
