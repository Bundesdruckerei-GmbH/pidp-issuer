/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain.data;

import de.bdr.pidp.issuer.authorization.core.domain.Requests;

public sealed interface AuthSessionView permits ParAuthSession, AuthorizeAuthSession, FinishAuthorizationAuthSession,
    TokenAuthSession, RefreshTokenAuthSession, TokenIntrospectAuthSession {
    Requests getNextExpectedRequest();
}
