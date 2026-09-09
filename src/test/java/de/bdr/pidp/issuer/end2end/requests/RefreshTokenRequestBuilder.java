/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.end2end.requests;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.openid.connect.sdk.Nonce;
import de.bdr.pidp.issuer.testdata.ClientIds;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.springframework.http.HttpMethod;

public class RefreshTokenRequestBuilder extends RequestBuilder<RefreshTokenRequestBuilder> {
    public static RefreshTokenRequestBuilder valid(String dpopNonce, String attestationChallenge, String refreshToken) {
        return new RefreshTokenRequestBuilder()
            .withContentType("application/x-www-form-urlencoded; charset=utf-8")
            .withGrantType(GrantType.REFRESH_TOKEN.getValue())
            .withClientId(ClientIds.validClientIdForSelfSigned().toString())
            .withDPoPHeader(dpopNonce)
            .withClientAttestation(TestUtils.getValidClientAttestationJwt().serialize())
            .withClientAttestationPoP(TestUtils.getValidClientAttestationPopJwt(attestationChallenge).serialize())
            .withRefreshToken(refreshToken)
            .withOptionalScope("pid");
    }

    public RefreshTokenRequestBuilder() {
        super(HttpMethod.POST);
        withUrl(TokenRequestBuilder.getTokenPath());
    }

    public RefreshTokenRequestBuilder withGrantType(String grantType) {
        withFormParam("grant_type", grantType);
        return this;
    }

    public RefreshTokenRequestBuilder withRefreshToken(String refreshToken) {
        withFormParam("refresh_token", refreshToken);
        return this;
    }

    public RefreshTokenRequestBuilder withClientId(String clientId) {
        withFormParam("client_id", clientId);
        return this;
    }

    public RefreshTokenRequestBuilder withDPoPHeader(String dpopNonce) {
        final SignedJWT dpopProof = TestUtils.getDPoPProof(HttpMethod.POST, TokenRequestBuilder.getTokenUri(), Nonce.parse(dpopNonce));
        withHeader("dpop", dpopProof.serialize());
        return this;
    }

    public RefreshTokenRequestBuilder withClientAttestation(String clientAttestation) {
        withHeader("OAuth-Client-Attestation", clientAttestation);
        return this;
    }

    public RefreshTokenRequestBuilder withClientAttestationPoP(String clientAttestationPoP) {
        withHeader("OAuth-Client-Attestation-PoP", clientAttestationPoP);
        return this;
    }

    public RefreshTokenRequestBuilder withOptionalScope(String scope) {
        withFormParam("scope", scope);
        return this;
    }
}
