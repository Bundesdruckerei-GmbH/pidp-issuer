/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core.signer;

import java.security.cert.X509Certificate;
import java.util.List;

public interface CredentialSigner {
    Algorithm getAlgorithm();
    List<X509Certificate> getCertificateChain();

    /**
     * @param data raw data to be signed (not hashed)
     * @return a concat encoded signature of the input
     */
    byte[] sign(byte[] data);
}
