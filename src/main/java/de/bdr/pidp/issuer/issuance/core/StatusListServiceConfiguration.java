/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core;

import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

@Setter
@Getter
@ToString
@Validated
@Configuration
@ConfigurationProperties(prefix = "pidi.statuslistservice")
public class StatusListServiceConfiguration {

    @NotNull
    private String baseUrl;

    private String apiKey;
    private String poolId;
}
