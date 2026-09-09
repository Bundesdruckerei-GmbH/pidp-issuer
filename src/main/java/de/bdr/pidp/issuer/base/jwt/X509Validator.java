/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwt;

import de.bdr.pidp.issuer.base.logging.LogType;
import lombok.extern.slf4j.Slf4j;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXReason;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
public class X509Validator {

    private final CertPathValidator cpv;
    private final CertificateFactory cf;
    private final boolean allowSelfSigned;

    public X509Validator(boolean allowSelfSigned) {
        this.allowSelfSigned = allowSelfSigned;
        try {
            cpv = CertPathValidator.getInstance("PKIX");
            cf = CertificateFactory.getInstance("X.509");
        } catch (NoSuchAlgorithmException | CertificateException e) {
            throw new IllegalStateException(e);
        }
    }

    public void validate(Set<X509Certificate> anchorCerts, List<X509Certificate> certChain) throws CertificateException, CertPathValidatorException {
        try {
            Set<TrustAnchor> trustAnchors = anchorCerts.stream().map(anchorCert -> new TrustAnchor(anchorCert, null)).collect(Collectors.toSet());
            var params = new PKIXParameters(trustAnchors);

            /*
            Default checkers are:
             UntrustedChecker (check whether a specified certificate is distrusted),
             AlgorithmChecker (checks required algorithm constraints),
             KeyChecker (keyCertSign bit is set in CA's),
             ConstraintsChecker (basic constraints = path length and name constraints),
             PolicyChecker (certificate policies, policy mappings, policy constraints and policy qualifiers),
             BasicChecker (signature, validity, and subject/issuer name chaining).
            Add additional checkers.
             */
            params.addCertPathChecker(new X509VersionChecker());
            params.addCertPathChecker(new X509CriticalExtensionsChecker());

            params.setRevocationEnabled(false);

            var certPath = cf.generateCertPath(certChain);
            var valRes = (PKIXCertPathValidatorResult) cpv.validate(certPath, params);
            var trustAnchorCert = valRes.getTrustAnchor().getTrustedCert();
            if (certChain.size() > 1 && trustAnchorCert.equals(certChain.getLast())) {
                throw new CertPathValidatorException("The certificate chain must not contain the trust anchor", null, certPath, certChain.size() - 1, ValidationExceptionReason.CHAIN_CONTAINS_TRUST_ANCHOR);
            }
            var selfSigned = isSelfSigned(certChain.getFirst());
            if (!allowSelfSigned && selfSigned) {
                throw new CertPathValidatorException("Self signed certificates are not allowed", null, certPath, 0, ValidationExceptionReason.SELF_SIGNED);
            }
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(e);
        } catch (CertPathValidatorException e) {
            logCertErrorState(e.getReason());
            throw e;
        }
    }

    private void logCertErrorState(CertPathValidatorException.Reason reason) {
        var message = switch (reason) {
            case CertPathValidatorException.BasicReason.EXPIRED -> "expired certificate";
            case PKIXReason.PATH_TOO_LONG,
                 ValidationExceptionReason.CHAIN_CONTAINS_TRUST_ANCHOR,
                 ValidationExceptionReason.INVALID_VERSION,
                 ValidationExceptionReason.MISSING_KEY_USAGE,
                 ValidationExceptionReason.NOT_ALLOWED_CRITICAL_EXTENSION -> "invalid certificate";
            default -> "untrusted certificate";
        };
        try (var _ = LogType.mdcContext(LogType.Value.SECURITY)) {
            log.warn("{}, reason: {}", message, reason);
        }
    }

    private boolean isSelfSigned(X509Certificate cert) {
        try {
            cert.verify(cert.getPublicKey());
            return true;
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException |
                 NoSuchProviderException | SignatureException _) {
            return false;
        }
    }

    public enum ValidationExceptionReason implements CertPathValidatorException.Reason {
        CHAIN_CONTAINS_TRUST_ANCHOR,
        SELF_SIGNED,
        INVALID_VERSION,
        NOT_ALLOWED_CRITICAL_EXTENSION,
        MISSING_KEY_USAGE
    }
}
