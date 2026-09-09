/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwt;

import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;

public class X509VersionChecker extends AbstractX509CertPathChecker {

    private static final int REQUIRED_CERT_VERSION = 3;

    @Override
    public void check(X509Certificate cert) throws CertPathValidatorException {
        if (cert.getVersion() != REQUIRED_CERT_VERSION) {
            throw new CertPathValidatorException("The certificate version is not valid", null, null, -1, X509Validator.ValidationExceptionReason.INVALID_VERSION);
        }
    }
}
