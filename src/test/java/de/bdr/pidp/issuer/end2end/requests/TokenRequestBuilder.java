/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.end2end.requests;


import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.openid.connect.sdk.Nonce;
import de.bdr.pidp.issuer.testdata.TestConfig;
import de.bdr.pidp.issuer.testdata.TestUtils;
import org.springframework.http.HttpMethod;

import java.net.URI;
import java.util.List;

import static de.bdr.pidp.issuer.testdata.ValidTestData.CODE_VERIFIER;
import static de.bdr.pidp.issuer.testdata.ValidTestData.REDIRECT_URI;

public class TokenRequestBuilder extends RequestBuilder<TokenRequestBuilder> {

    public static TokenRequestBuilder valid(String dpopNonce) {
        return new TokenRequestBuilder()
            .withContentType("application/x-www-form-urlencoded; charset=utf-8")
            .withRedirectUri(REDIRECT_URI)
            .withGrantType(GrantType.AUTHORIZATION_CODE.getValue())
            .withCodeVerifier(CODE_VERIFIER)
            .withKeyAttestationDPoPHeader(dpopNonce);
    }

    public static String getTokenPath() {
        return "/token";
    }

    public static URI getTokenUri() {
        return URI.create(TestConfig.pidiBaseUrl() + getTokenPath());
    }

    public TokenRequestBuilder() {
        super(HttpMethod.POST);
        withUrl(getTokenPath());
    }

    public TokenRequestBuilder withRedirectUri(String redirectUri) {
        withFormParam("redirect_uri", redirectUri);
        return this;
    }

    public TokenRequestBuilder withGrantType(String grantType) {
        withFormParam("grant_type", grantType);
        return this;
    }

    public TokenRequestBuilder withAuthorizationCode(String authorizationCode) {
        withFormParam("code", authorizationCode);
        return this;
    }

    public TokenRequestBuilder withCodeVerifier(String codeVerifier) {
        withFormParam("code_verifier", codeVerifier);
        return this;
    }

    public TokenRequestBuilder withKeyAttestationDPoPHeader(String dpopNonce) {
        var keyAttestationJwt = TestUtils.getKeyAttestationJwtForDPoP(dpopNonce, List.of(TestUtils.DEVICE_KEY_PAIR.toPublicJWK()));
        var dpopProof = TestUtils.getDPoPProof(httpMethod, getTokenUri(), Nonce.parse(dpopNonce), keyAttestationJwt).serialize();
        withHeader("dpop", dpopProof);
        return this;
    }
}
