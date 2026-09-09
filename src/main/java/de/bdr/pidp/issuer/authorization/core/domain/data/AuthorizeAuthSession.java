/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain.data;

import de.bdr.pidp.issuer.authorization.core.domain.Requests;

import java.time.Instant;

public sealed interface AuthorizeAuthSession extends AuthSessionView permits AuthSession {
    Instant getRequestUriExpirationTime();
    String getClientId();
    long getSessionId();
    void addGeneratedAuthorizeProperties(String issuerState);
    void setNextExpectedRequest(Requests nextExpectedRequest);
}
