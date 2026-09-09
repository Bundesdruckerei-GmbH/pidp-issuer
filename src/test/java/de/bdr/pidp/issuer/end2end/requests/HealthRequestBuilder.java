/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.end2end.requests;

import org.springframework.http.HttpMethod;

public class HealthRequestBuilder extends RequestBuilder<HealthRequestBuilder> {
    public HealthRequestBuilder() {
        super(HttpMethod.GET);
    }

    public static HealthRequestBuilder valid() {
        var path = getHealthPath();
        return new HealthRequestBuilder()
            .withUrl(path);
    }

    public static String getHealthPath() {
        return "/health";
    }
}
