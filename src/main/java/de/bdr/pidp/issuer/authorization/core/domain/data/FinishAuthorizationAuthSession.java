/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain.data;

import de.bdr.pidp.issuer.authorization.core.domain.Requests;

import java.time.Instant;

public sealed interface FinishAuthorizationAuthSession extends AuthSessionView, AuthSessionDPoPView permits AuthSession {
    String getIssuerState();
    String getRedirectUri();
    String getState();
    void addGeneratedFinishAuthorizationProperties(String authorizationCode, Instant authorizationCodeExpirationTime);
    void setNextExpectedRequest(Requests nextExpectedRequest);
}
