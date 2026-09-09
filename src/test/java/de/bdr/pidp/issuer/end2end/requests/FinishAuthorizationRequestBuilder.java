/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.end2end.requests;


import org.springframework.http.HttpMethod;

public class FinishAuthorizationRequestBuilder extends RequestBuilder<FinishAuthorizationRequestBuilder> {


    public FinishAuthorizationRequestBuilder() {
        super(HttpMethod.GET);

    }

    public static FinishAuthorizationRequestBuilder valid(String issuerState) {
        return new FinishAuthorizationRequestBuilder()
            .withUrl(getFinishAuthorizationPath())
            .withIssuerState(issuerState);
    }

    public static String getFinishAuthorizationPath() {
        return "/finish-authorization";
    }

    public FinishAuthorizationRequestBuilder withIssuerState(String issuerState) {
        withQueryParam("issuer_state", issuerState);
        return this;
    }
}
