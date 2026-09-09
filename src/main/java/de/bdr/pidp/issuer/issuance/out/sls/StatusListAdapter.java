/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.out.sls;

import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.issuance.core.StatusListServiceConfiguration;
import de.bdr.pidp.issuer.issuance.core.StatusReference;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.support.RestClientAdapter;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;

import java.util.List;
import java.util.Objects;

@NullMarked
@Slf4j
@Service
public class StatusListAdapter {
    private final StatusListServiceConfiguration configuration;
    private final StatusListClient statusListClient;

    public StatusListAdapter(StatusListServiceConfiguration statusListServiceConfiguration, RestClient.Builder restClientBuilder) {
        configuration = statusListServiceConfiguration;
        statusListClient = HttpServiceProxyFactory
            .builderFor(RestClientAdapter.create(restClientBuilder.baseUrl(configuration.getBaseUrl()).build()))
            .build().createClient(StatusListClient.class);
    }

    public List<StatusReference> acquireFreeIndices(int amount) {
        if (amount <= 0) {
            throw new IllegalArgumentException("Requested amount of status references must be greater than 0");
        }
        try {
            References response = statusListClient.createReferences(
                configuration.getApiKey(),
                configuration.getPoolId(),
                amount
            );
            return Objects.requireNonNull(response).references();
        } catch (Exception e) {
            throw new PidServerException("Could not acquire free index from status list service", e);
        }
    }
}
