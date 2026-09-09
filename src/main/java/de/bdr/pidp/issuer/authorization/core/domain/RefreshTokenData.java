/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain;

import com.nimbusds.jwt.SignedJWT;

public record RefreshTokenData(SignedJWT refreshToken, long expiresIn) {
}
