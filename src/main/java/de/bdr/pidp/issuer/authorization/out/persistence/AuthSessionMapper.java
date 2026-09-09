/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.out.persistence;

import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSession;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.jspecify.annotations.NullMarked;

@NullMarked
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class AuthSessionMapper {
    public static AuthSession map(final AuthSessionEntity authSessionEntity) {
        return new AuthSession(
            authSessionEntity.getSessionId(),
            authSessionEntity.getAccessTokenID(),
            authSessionEntity.getAuthorizationCode(),
            authSessionEntity.getAuthorizationCodeExpirationTime(),
            authSessionEntity.getClientAttestationStatusListRefURI(),
            authSessionEntity.getClientAttestationStatusListRefIndex(),
            authSessionEntity.getClientId(),
            authSessionEntity.getCodeChallenge(),
            authSessionEntity.getCodeChallengeMethod(),
            authSessionEntity.getDpopNonce(),
            authSessionEntity.getDpopNonceExpirationTime(),
            authSessionEntity.getSeedCredentialData(),
            authSessionEntity.getSeedCredentialRef(),
            authSessionEntity.getSeedCredentialSub(),
            authSessionEntity.getSeedCredentialExpirationTime(),
            authSessionEntity.getIssuerState(),
            authSessionEntity.getRedirectUri(),
            authSessionEntity.getRefreshTokenID(),
            authSessionEntity.getRequestUri(),
            authSessionEntity.getRequestUriExpirationTime(),
            authSessionEntity.getScope(),
            authSessionEntity.getState(),
            authSessionEntity.getNextExpectedRequest()
        );
    }
}
