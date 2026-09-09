/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core.configuration;

import de.governikus.panstar.sdk.saml.configuration.SamlConfiguration;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;

/**
 * this SAML configuration supports
 * multiple signature certificates.
 *     (for use in a test client and on key rollover),
 *     this results in different <code>SamlKeyMaterial</code> instances<br>
 *     these are grouped in <code>SpecificConfiguration</code> instances</code>
 */
@Slf4j
public class MultiSamlConfigurationImpl implements MultiSamlConfiguration {

    @Getter
    private final String responseUrl;

    @Getter
    private final List<SamlConfiguration> configurations;

    public MultiSamlConfigurationImpl(AutentConfigurationImpl config, String responseUrl) {
        this.responseUrl = responseUrl;
        configurations = new ArrayList<>();
        var certs = config.getAutentSamlSignatureCertificates();
        for (var cert : certs) {
            configurations.add(new SpecificConfiguration(config, this.responseUrl, cert));
        }
    }
}
