/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.end2end.requests;

import org.springframework.http.HttpMethod;

public class CredentialIssuerMetadataRequestBuilder extends RequestBuilder<CredentialIssuerMetadataRequestBuilder> {
    public CredentialIssuerMetadataRequestBuilder() {
        super(HttpMethod.GET);
    }

    public static CredentialIssuerMetadataRequestBuilder valid() {
        var path = getCredentialIssuerMetadataUrl();
        return new CredentialIssuerMetadataRequestBuilder()
            .withUrl(path);
    }

    public static String getCredentialIssuerMetadataUrl() {
        return "/.well-known/openid-credential-issuer";
    }
}
