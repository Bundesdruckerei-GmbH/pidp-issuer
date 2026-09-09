/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.end2end.requests;


import de.bdr.pidp.issuer.testdata.ClientIds;
import org.springframework.http.HttpMethod;

public class AuthorizationRequestBuilder extends RequestBuilder<AuthorizationRequestBuilder> {


    public AuthorizationRequestBuilder() {
        super(HttpMethod.GET);
        withUrl(getAuthorizationPath());
    }

    public static AuthorizationRequestBuilder valid(String requestUri) {
        return new AuthorizationRequestBuilder()
            .withClientId(ClientIds.validClientIdForSelfSigned().toString())
            .withRequestUri(requestUri);
    }

    public static String getAuthorizationPath() {
        return "/authorize";
    }

    public AuthorizationRequestBuilder withClientId(String clientId) {
        withQueryParam("client_id", clientId);
        return this;
    }

    public AuthorizationRequestBuilder withRequestUri(String requestUri) {
        withQueryParam("request_uri", requestUri);
        return this;
    }
}
