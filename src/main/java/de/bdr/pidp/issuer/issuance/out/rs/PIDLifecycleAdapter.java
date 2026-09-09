/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.out.rs;

import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.PidpServiceUnavailableException;
import de.bdr.pidp.issuer.base.RevocationServiceConfiguration;
import de.bdr.pidp.issuer.base.jwt.StatusListRef;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.support.RestClientAdapter;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;

import java.time.Instant;
import java.util.Collection;

@Component
public class PIDLifecycleAdapter {

    private final PIDLifecycleClient pidLifecycleClient;
    private final String apiKey;

    public PIDLifecycleAdapter(RevocationServiceConfiguration config, RestClient.Builder restClientBuilder) {
        pidLifecycleClient = HttpServiceProxyFactory
            .builderFor(RestClientAdapter.create(restClientBuilder.baseUrl(config.getBaseUrl()).build()))
            .build().createClient(PIDLifecycleClient.class);
        apiKey = config.getApiKey();
    }

    public void registerPIDs(String pidMasterTokenID, Instant expiration, Collection<StatusListRef> statusLists) {
        var credentialInfoRefs = statusLists.stream()
            .map(statusListRef -> new TokenStatusListRef(statusListRef.uri(), statusListRef.index()))
            .map(tokenStatusListRef -> new CredentialInfoRef(expiration, tokenStatusListRef))
            .toList();
        var ref = new BatchCredentialInfoRef(pidMasterTokenID, credentialInfoRefs);

        try {
            pidLifecycleClient.registerCredential(apiKey, ref);
        } catch (HttpClientErrorException e) {
            throw new PidServerException("Revocation lifecycle request rejected", e);
        } catch (RestClientException e) {
            throw new PidpServiceUnavailableException("Revocation lifecycle request failed due to an unexpected error", e);
        }
    }
}
