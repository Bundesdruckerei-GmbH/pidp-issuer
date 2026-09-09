/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwt;

import org.jspecify.annotations.Nullable;

import java.security.cert.CertPathValidatorException;
import java.security.cert.PKIXReason;
import java.security.cert.X509Certificate;
import java.util.Set;

public class X509CriticalExtensionsChecker extends AbstractX509CertPathChecker {

    // Definition of standard-OIDs
    private static final String OID_BASIC_CONSTRAINTS = "2.5.29.19";
    private static final String OID_KEY_USAGE         = "2.5.29.15";
    private static final String OID_CRL_DIST_POINTS   = "2.5.29.31";
    private static final String OID_CRT_POLYCIES      = "2.5.29.32";
    private static final Set<String> ALLOWED_CRITICAL_EXTENSIONS = Set.of(OID_BASIC_CONSTRAINTS, OID_KEY_USAGE, OID_CRL_DIST_POINTS, OID_CRT_POLYCIES);
    private static final int KEY_CERT_SIGN_INDEX = 5;

    @Override
    public void check(X509Certificate cert) throws CertPathValidatorException {
        // whitelist check
        Set<String> criticalExtensionOIDs = cert.getCriticalExtensionOIDs();
        if (criticalExtensionOIDs != null && !criticalExtensionOIDs.isEmpty()) {
            for (String oid : criticalExtensionOIDs) {
                if (!ALLOWED_CRITICAL_EXTENSIONS.contains(oid)) {
                    throw new CertPathValidatorException("The critical extension '" + oid + "' is not allowed", null, null, -1, X509Validator.ValidationExceptionReason.NOT_ALLOWED_CRITICAL_EXTENSION);
                }
            }
        }
        checkKeyUsage(cert.getKeyUsage(), cert.getBasicConstraints());
    }

    private void checkKeyUsage(boolean @Nullable [] keyUsage, int basicConstraints) throws CertPathValidatorException {
        // "2.5.29.15" key usage check
        if (keyUsage == null) {
            throw new CertPathValidatorException("Missing key usage completely", null, null, -1, X509Validator.ValidationExceptionReason.MISSING_KEY_USAGE);
        }
        if (basicConstraints == -1) { // is target certificate
            if (keyUsage[KEY_CERT_SIGN_INDEX]) {
                throw new CertPathValidatorException("key usage 'keyCertSign' is not allowed", null, null, -1, PKIXReason.INVALID_KEY_USAGE);
            }
        } else { // is CA
            if (!keyUsage[KEY_CERT_SIGN_INDEX]) {
                throw new CertPathValidatorException("key usage 'keyCertSign' is required", null, null, -1, PKIXReason.INVALID_KEY_USAGE);
            }
        }
    }
}
