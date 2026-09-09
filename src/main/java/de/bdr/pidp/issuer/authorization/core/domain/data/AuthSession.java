/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.domain.data;

import de.bdr.pidp.issuer.authorization.core.domain.Requests;
import de.bdr.pidp.issuer.authorization.core.domain.SeedCredential;
import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.base.jwt.StatusListRef;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.time.Instant;

@Getter
@AllArgsConstructor
public final class AuthSession implements ParAuthSession, AuthorizeAuthSession, FinishAuthorizationAuthSession,
    TokenAuthSession, RefreshTokenAuthSession, TokenIntrospectAuthSession, SeedCredentialDataAuthSession {
    public AuthSession(long sessionId) {
        this.sessionId = sessionId;
    }

    private final long sessionId;
    private @Nullable String accessTokenID;
    private @Nullable String authorizationCode;
    private @Nullable Instant authorizationCodeExpirationTime;
    private @Nullable URI clientAttestationStatusListRefURI;
    private @Nullable Integer clientAttestationStatusListRefIndex;
    private @Nullable String clientId;
    private @Nullable String codeChallenge;
    private @Nullable String codeChallengeMethod;
    private @Nullable String dpopNonce;
    private @Nullable Instant dpopNonceExpirationTime;
    private @Nullable String seedCredentialData;
    private @Nullable String seedCredentialRef;
    private @Nullable String seedCredentialSub;
    private @Nullable Instant seedCredentialExpirationTime;
    private @Nullable String issuerState;
    private @Nullable String redirectUri;
    private @Nullable String refreshTokenID;
    private @Nullable String requestUri;
    private @Nullable Instant requestUriExpirationTime;
    private @Nullable String scope;
    private @Nullable String state;
    @Setter
    private @Nullable Requests nextExpectedRequest;

    @Override
    public @Nullable StatusListRef getClientAttestationStatusListRef() {
        if (clientAttestationStatusListRefURI != null && clientAttestationStatusListRefIndex != null) {
            return new StatusListRef(clientAttestationStatusListRefURI, clientAttestationStatusListRefIndex);
        }
        return null;
    }

    @Override
    public void addValidatedRequestParams(String codeChallenge, String codeChallengeMethod, String clientId, String redirectUri, String scope, @Nullable StatusListRef clientAttestationStatusListRef, @Nullable String state) {
        this.codeChallenge = codeChallenge;
        this.codeChallengeMethod = codeChallengeMethod;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.scope = scope;
        this.state = state;
        if (clientAttestationStatusListRef != null) {
            this.clientAttestationStatusListRefURI = clientAttestationStatusListRef.uri();
            this.clientAttestationStatusListRefIndex = clientAttestationStatusListRef.index();
        }
    }

    @Override
    public void addGeneratedParProperties(String requestUri, Instant requestUriExpirationTime) {
        this.requestUri = requestUri;
        this.requestUriExpirationTime = requestUriExpirationTime;
    }

    @Override
    public void addGeneratedAuthorizeProperties(String issuerState) {
        this.issuerState = issuerState;
    }

    @Override
    public void setDPoPNonce(Nonce dpopNonce) {
        this.dpopNonce = dpopNonce.nonce();
        this.dpopNonceExpirationTime = dpopNonce.expirationTime();
    }

    @Override
    public void addGeneratedFinishAuthorizationProperties(String authorizationCode, Instant authorizationCodeExpirationTime) {
        this.authorizationCode = authorizationCode;
        this.authorizationCodeExpirationTime = authorizationCodeExpirationTime;
    }

    @Override
    public void addGeneratedTokenProperties(SeedCredential seedCredential, String accessTokenID) {
        this.accessTokenID = accessTokenID;
        this.seedCredentialData = seedCredential.value();
        this.seedCredentialSub = seedCredential.subject();
        this.seedCredentialRef = seedCredential.reference();
        this.seedCredentialExpirationTime = seedCredential.exp();
    }

    @Override
    public void addValidatedRefreshTokenRequestParams(String clientId, String scope, SeedCredential seedCredential) {
        this.clientId = clientId;
        this.scope = scope;
        this.seedCredentialData = seedCredential.value();
        this.seedCredentialSub = seedCredential.subject();
        this.seedCredentialRef = seedCredential.reference();
        this.seedCredentialExpirationTime = seedCredential.exp();
    }

    @Override
    public void addGeneratedAccessTokenId(String accessTokenID) {
        this.accessTokenID = accessTokenID;
    }
}
