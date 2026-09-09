/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.clientconfiguration.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Setter
@Getter
@Validated
@Configuration
@ConfigurationProperties(prefix = "pidi.client")
public class ClientConfiguration {
    /**
     * When real data is processed, the trust anchors for key- and client-attestation validation will be obtained from a trust list,
     * otherwise from the locally configured client-attestation-cert & key-attestation-cert properties
     */
    private boolean processRealData;
    private Map<UUID, List<String>> clientAttestationCert;
    private Map<UUID, List<String>> keyAttestationCert;
    private List<UUID> keyAttestationAtTokenRequestDisabledClients = new ArrayList<>();
}
