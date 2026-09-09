/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.config.model;

import com.nimbusds.jose.jwk.JWKSet;
import org.jspecify.annotations.NullMarked;

@NullMarked
public interface RequestEncryptionJWKSupplier {
    JWKSet jwks();
}
