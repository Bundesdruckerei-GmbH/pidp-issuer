/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base;

import jakarta.validation.constraints.NotNull;
import lombok.Getter;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

@Getter
public abstract class BaseUrlConfiguration {
    /**
     * the base url of the pid-issuer
     */
    private URL baseUrl;

    public void setBaseUrl(@NotNull URL baseUrl) throws MalformedURLException {
        if (baseUrl.getPath().endsWith("/")) {
            String urlString = baseUrl.toString().replaceAll("/$", "");
            this.baseUrl = URI.create(urlString).toURL();
        } else {
            this.baseUrl = baseUrl;
        }
    }

    public String getCredentialIssuerIdentifier() {
        return getBaseUrl().toString();
    }
}
