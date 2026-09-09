/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain.data;

import de.bdr.pidp.issuer.authorization.core.domain.Requests;
import de.bdr.pidp.issuer.authorization.core.domain.SeedCredential;

public sealed interface RefreshTokenAuthSession extends AuthSessionView, AuthSessionDPoPView permits AuthSession {
    String getScope();
    void setNextExpectedRequest(Requests nextExpectedRequest);
    void addValidatedRefreshTokenRequestParams(String clientId, String scope, SeedCredential seedCredential);
    void addGeneratedAccessTokenId(String accessTokenID);
}
