/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.end2end.requests;

import org.springframework.http.HttpMethod;

public class NonceRequestBuilder extends RequestBuilder<NonceRequestBuilder> {
    public NonceRequestBuilder() {
        super(HttpMethod.POST);
    }

    public static NonceRequestBuilder valid() {
        var path = getNoncePath();
        return new NonceRequestBuilder()
            .withUrl(path);
    }

    public static String getNoncePath() {
        return "/nonce";
    }
}
