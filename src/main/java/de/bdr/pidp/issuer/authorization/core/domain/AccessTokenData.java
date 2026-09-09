/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain;

import com.nimbusds.jwt.SignedJWT;

import java.util.UUID;

public record AccessTokenData(UUID accessTokenID, SignedJWT accessToken, String tokenType, long expiresIn) {
}
