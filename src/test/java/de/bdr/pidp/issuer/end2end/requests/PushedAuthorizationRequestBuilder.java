/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.end2end.requests;

import com.nimbusds.oauth2.sdk.id.State;
import de.bdr.pidp.issuer.testdata.ClientIds;
import de.bdr.pidp.issuer.testdata.TestUtils;
import de.bdr.pidp.issuer.testdata.ValidTestData;
import org.springframework.http.HttpMethod;

public class PushedAuthorizationRequestBuilder extends RequestBuilder<PushedAuthorizationRequestBuilder> {

    public PushedAuthorizationRequestBuilder() {
        super(HttpMethod.POST);
    }

    /**
     * Creates a valid PushedAuthorizationRequest by default.
     */
    public static PushedAuthorizationRequestBuilder valid(String attestationChallenge) {
        return new PushedAuthorizationRequestBuilder()
            .withUrl(getPARPath())
            .withClientId(ClientIds.validClientIdForSelfSigned().toString())
            .withClientAttestation(TestUtils.getValidClientAttestationJwt().serialize())
            .withClientAttestationPoP(TestUtils.getValidClientAttestationPopJwt(attestationChallenge).serialize())
            .withCodeChallengeMethod("S256")
            .withCodeChallenge(ValidTestData.CODE_CHALLENGE)
            .withResponseType("code")
            .withScope("pid")
            .withState(new State().getValue())
            .withContentType("application/x-www-form-urlencoded")
            .withRedirectUri(ValidTestData.REDIRECT_URI);
    }


    public static String getPARPath() {
        return "/par";
    }

    public PushedAuthorizationRequestBuilder withCodeChallenge(String codeChallenge) {
        withFormParam("code_challenge", codeChallenge);
        return this;
    }

    public PushedAuthorizationRequestBuilder withCodeChallengeMethod(String codeChallengeMethod) {
        withFormParam("code_challenge_method", codeChallengeMethod);
        return this;
    }

    public PushedAuthorizationRequestBuilder withClientId(String clientId) {
        withFormParam("client_id", clientId);
        return this;
    }

    public PushedAuthorizationRequestBuilder withRedirectUri(String redirectUri) {
        withFormParam("redirect_uri", redirectUri);
        return this;
    }

    public PushedAuthorizationRequestBuilder withState(String state) {
        withFormParam("state", state);
        return this;
    }

    public PushedAuthorizationRequestBuilder withResponseType(String responseType) {
        withFormParam("response_type", responseType);
        return this;
    }

    public PushedAuthorizationRequestBuilder withScope(String scope) {
        withFormParam("scope", scope);
        return this;
    }

    public PushedAuthorizationRequestBuilder withClientAttestation(String clientAttestation) {
        withHeader("OAuth-Client-Attestation", clientAttestation);
        return this;
    }

    public PushedAuthorizationRequestBuilder withClientAttestationPoP(String clientAttestationPoP) {
        withHeader("OAuth-Client-Attestation-PoP", clientAttestationPoP);
        return this;
    }
}
