/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.jwt;

import com.nimbusds.jose.proc.SecurityContext;

import java.security.cert.X509Certificate;
import java.util.Set;

public interface X509SecurityContext extends SecurityContext {
    Set<X509Certificate> getTrustAnchorCertificates();
}
