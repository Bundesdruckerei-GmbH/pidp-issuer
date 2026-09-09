/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain;

import de.bdr.pidp.issuer.base.Nonce;

public record RefreshTokenResult(AccessTokenData accessTokenData, Nonce nonce) {
}
