/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain.data;

import de.bdr.pidp.issuer.authorization.core.domain.Requests;
import de.bdr.pidp.issuer.base.jwt.StatusListRef;
import org.jspecify.annotations.Nullable;

import java.time.Instant;

public sealed interface ParAuthSession extends AuthSessionView permits AuthSession {
    void addValidatedRequestParams(String codeChallenge, String codeChallengeMethod, String clientId, String redirectUri, String scope, @Nullable StatusListRef clientAttestationStatusListRef, @Nullable String state);
    void addGeneratedParProperties(String requestUri, Instant requestUriExpirationTime);
    void setNextExpectedRequest(Requests nextExpectedRequest);
}
