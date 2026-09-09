/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain.data;

import de.bdr.pidp.issuer.base.Nonce;

import java.time.Instant;

public sealed interface AuthSessionDPoPView permits FinishAuthorizationAuthSession, TokenAuthSession,
    RefreshTokenAuthSession, TokenIntrospectAuthSession {
    String getDpopNonce();
    Instant getDpopNonceExpirationTime();
    void setDPoPNonce(Nonce nonce);
}
