/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization;

import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.testdata.TestConfig;

import java.net.MalformedURLException;
import java.net.URI;
import java.time.Duration;

public class ConfigTestData {

    public static final AuthorizationConfiguration AUTH_CONFIG;

    static {
        AUTH_CONFIG = new AuthorizationConfiguration();
        AUTH_CONFIG.setProcessRealData(false);
        AUTH_CONFIG.setChallengeEnabled(true);
        AUTH_CONFIG.setAccessTokenLifetime(Duration.ofSeconds(60));
        AUTH_CONFIG.setAuthorizationCodeLifetime(Duration.ofSeconds(60));
        AUTH_CONFIG.setRequestUriLifetime(Duration.ofSeconds(60));
        AUTH_CONFIG.setPopNonceLifetime(Duration.ofSeconds(60));
        AUTH_CONFIG.setProofTimeTolerance(Duration.ofSeconds(60));
        AUTH_CONFIG.setProofValidity(Duration.ofSeconds(60));
        AUTH_CONFIG.setSessionExpirationTime(Duration.ofMinutes(60));
        AUTH_CONFIG.setKeyStorageTypes(new String[]{"iso_18045_high", "iso_18045_moderate", "iso_18045_enhanced-basic"});
        AUTH_CONFIG.setUserAuthenticationTypes(new String[]{"iso_18045_high", "iso_18045_moderate", "iso_18045_basic"});
        AUTH_CONFIG.setAtSigAlias("pp_at_auth_local");
        try {
            AUTH_CONFIG.setBaseUrl(URI.create(TestConfig.pidiBaseUrl()).toURL());
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }
}
