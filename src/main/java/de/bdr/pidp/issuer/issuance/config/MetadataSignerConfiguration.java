/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

@Setter
@Getter
@Validated
@Configuration
@ConfigurationProperties(prefix = "pidi.metadata")
public class MetadataSignerConfiguration {
    private String signerPath;
    private String signerPassword;
    private String signerAlias;
    private String accessCertificateAlias;
}
