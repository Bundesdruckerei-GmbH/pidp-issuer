/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core;

import de.bdr.pidp.issuer.base.BaseUrlConfiguration;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Getter
@Setter
@Validated
@Configuration
@ConfigurationProperties(prefix = "pidi.authorization")
public class AuthorizationConfiguration extends BaseUrlConfiguration {

    private boolean processRealData;

    private boolean challengeEnabled;

    /**
     * the lifetime of a request uri
     */
    private Duration requestUriLifetime;

    /**
     * the lifetime of an access token
     */
    private Duration accessTokenLifetime;

    /**
     * the maximum lifetime of a refresh token
     */
    private Duration refreshTokenMaxLifetime;

    /**
     * The lifetime of a nonce used in a Proof of Possession, that is also eligible for attestation challenges which terminology describes it as:
     * "A String that is the input to a cryptographic challenge-response pattern, used to detect replay attacks. Within OAuth, this is traditionally called a nonce."
     */
    private Duration popNonceLifetime;

    /**
     * lifetime of an authorization code
     */
    private Duration authorizationCodeLifetime;

    private Duration proofTimeTolerance;

    private Duration proofValidity;

    private Duration sessionExpirationTime;

    private String[] keyStorageTypes;

    private String[] userAuthenticationTypes;

    private String atSigAlias;

    private String rtSigAlias;

    private String rtSigAliasHsm;

    private String rtPath;

    private String rtPassword;

    private KMS kms;

    @Getter
    @Setter
    public static class KMS {

        private String transitPath;
    }

    public boolean allowSelfSignedAttestationCert() {
        return !processRealData;
    }
}
