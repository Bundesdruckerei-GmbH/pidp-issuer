/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain.data;

import de.bdr.pidp.issuer.authorization.core.domain.Requests;
import de.bdr.pidp.issuer.authorization.core.domain.SeedCredential;
import de.bdr.pidp.issuer.base.jwt.StatusListRef;

import java.time.Instant;

public sealed interface TokenAuthSession extends AuthSessionView, AuthSessionDPoPView permits AuthSession {
    Instant getAuthorizationCodeExpirationTime();
    String getClientId();
    String getScope();
    String getCodeChallenge();
    String getCodeChallengeMethod();
    String getRedirectUri();
    String getIssuerState();
    StatusListRef getClientAttestationStatusListRef();
    void addGeneratedTokenProperties(SeedCredential seedCredential, String accessTokenID);
    void setNextExpectedRequest(Requests nextExpectedRequest);
}
