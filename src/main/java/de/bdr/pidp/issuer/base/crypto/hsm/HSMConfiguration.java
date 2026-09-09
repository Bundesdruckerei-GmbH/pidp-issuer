/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.base.crypto.hsm;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.Map;

@Setter
@Validated
@Configuration
@ConfigurationProperties(prefix = "hsm")
class HSMConfiguration {

    /**
     * IP or hostname of the CXI device.
     */
    private String cxiDevice;
    /**
     * Timeout used when opening the CXI connection.
     * Spring will automatically convert the textual value (e.g. “3000ms”) to a {@link Duration}.
     */
    private Duration cxiConnectionTimeout;
    /**
     * Timeout used for execution of commands on CXI.
     */
    private Duration cxiCommandTimeout;
    /**
     * All crypto‑user definitions (ident, issuance, auth).  The map key is the logical name
     * that appears in the property path (e.g. {@code ident}, {@code issuance}, {@code auth}).
     *
     * <p>Using a map makes the bean extensible – you can add new users later without touching
     * Java code, only the properties file.
     */
    private Map<String, CryptoUser> cryptoUser;

    @Getter
    @Setter
    @AllArgsConstructor
    static class CryptoUser {
        private String name;
        private String password;
        /** Logical slot/group on the HSM (e.g. {@code SLOT_0002}). */
        private String group;
    }

    record HSMGroupConfiguration(String cxiDevice, Duration cxiConnectionTimeout, Duration cxiCommandTimeout, CryptoUser cryptoUser) {}

    @Bean(name = "hsmAuthenticationIssuance")
    @ConditionalOnProperty(name = "hsm.enabled", havingValue = "true")
    public HSMAuthenticationService hsmAuthenticationIssuance() {
        var config = new HSMGroupConfiguration(cxiDevice, cxiConnectionTimeout, cxiCommandTimeout, cryptoUser.get("issuance"));
        return new HSMAuthenticationService(config);
    }

    @Bean(name = "hsmSigningIssuance")
    @ConditionalOnProperty(name = "hsm.enabled", havingValue = "true")
    public HSMSigningService hsmSigningIssuance(HSMAuthenticationService hsmAuthenticationIssuance) {
        return new HSMSigningService(hsmAuthenticationIssuance);
    }

    @Bean(name = "hsmAuthenticationAuthorization")
    @ConditionalOnProperty(name = "hsm.enabled", havingValue = "true")
    public HSMAuthenticationService hsmAuthenticationAuthorization() {
        var config = new HSMGroupConfiguration(cxiDevice, cxiConnectionTimeout, cxiCommandTimeout, cryptoUser.get("authorization"));
        return new HSMAuthenticationService(config);
    }

    @Bean(name = "hsmSigningAuthorization")
    @ConditionalOnProperty(name = "hsm.enabled", havingValue = "true")
    public HSMSigningService hsmSigningAuthorization(HSMAuthenticationService hsmAuthenticationAuthorization) {
        return new HSMSigningService(hsmAuthenticationAuthorization);
    }

    @Bean(name = "hsmAuthenticationIdentification")
    @ConditionalOnProperty(name = "hsm.enabled", havingValue = "true")
    public HSMAuthenticationService hsmAuthenticationIdentification() {
        var config = new HSMGroupConfiguration(cxiDevice, cxiConnectionTimeout, cxiCommandTimeout, cryptoUser.get("identification"));
        return new HSMAuthenticationService(config);
    }

    @Bean(name = "hsmSigningIdentification")
    @ConditionalOnProperty(name = "hsm.enabled", havingValue = "true")
    public HSMSigningService hsmSigningIdentification(HSMAuthenticationService hsmAuthenticationIdentification) {
        return new HSMSigningService(hsmAuthenticationIdentification);
    }
}
