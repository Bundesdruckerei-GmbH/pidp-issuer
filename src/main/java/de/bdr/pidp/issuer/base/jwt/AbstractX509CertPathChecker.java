/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwt;

import org.jspecify.annotations.Nullable;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Set;

public abstract class AbstractX509CertPathChecker extends PKIXCertPathChecker {
    @Override
    public void init(boolean forward) throws CertPathValidatorException {
        // Note that this class supports both forward and reverse modes.
    }

    @Override
    public boolean isForwardCheckingSupported() {
        // Note that this class supports both forward and reverse modes.
        return true;
    }

    @Override
    public @Nullable Set<String> getSupportedExtensions() {
        return null;
    }

    @Override
    public void check(Certificate cert, Collection<String> unresolvedCritExts) throws CertPathValidatorException {
        if (cert instanceof X509Certificate x509Cert) {
            check(x509Cert);
        }
    }

    public abstract void check(X509Certificate cert) throws CertPathValidatorException;
}
