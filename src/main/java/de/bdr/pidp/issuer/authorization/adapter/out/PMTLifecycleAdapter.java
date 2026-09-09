/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.adapter.out;

import de.bdr.pidp.issuer.authorization.port.out.RefreshTokenLifecyclePortOut;
import de.bdr.pidp.issuer.base.PidServerException;
import de.bdr.pidp.issuer.base.PidpServiceUnavailableException;
import de.bdr.pidp.issuer.base.RevocationServiceConfiguration;
import de.bdr.pidp.issuer.base.jwt.StatusListRef;
import de.bdr.pidp.issuer.base.logging.LogType;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.support.RestClientAdapter;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;

import java.time.Instant;

@Slf4j
@Component
class PMTLifecycleAdapter implements RefreshTokenLifecyclePortOut {

    private final PMTLifecycleClient client;
    private final String apiKey;

    PMTLifecycleAdapter(RevocationServiceConfiguration config, RestClient.Builder restClientBuilder) {
        client = HttpServiceProxyFactory
            .builderFor(RestClientAdapter.create(restClientBuilder.baseUrl(config.getBaseUrl()).build()))
            .build().createClient(PMTLifecycleClient.class);
        apiKey = config.getApiKey();
    }

    @Override
    public void registerToken(String jti, String pseudonym, Instant expiration, @Nullable StatusListRef statusListRef) {
        try {
            var statusRef = statusListRef == null ? null : new PMTStatusListRef(statusListRef.uri(), statusListRef.index());
            var ref = new PIDMasterTokenRef(jti, expiration, pseudonym, statusRef);
            client.registerToken(apiKey, ref);
        } catch (HttpClientErrorException e) {
            throw new PidServerException("Revocation lifecycle request rejected", e);
        } catch (RestClientException e) {
            throw new PidpServiceUnavailableException("Revocation lifecycle request failed due to an unexpected error", e);
        }
    }

    @Override
    public boolean isTokenValid(String jti) {
        try {
            return client.fetchValidityStatus(apiKey, jti).isValid();
        } catch (HttpClientErrorException.NotFound e) {
            try (var _ = LogType.mdcContext(LogType.Value.SECURITY)) {
                log.error("Refresh token ID (jti) not found at revocation-service", e);
            }
            return false;
        } catch (HttpClientErrorException e) {
            throw new PidServerException("Revocation lifecycle status request rejected", e);
        } catch (RestClientException e) {
            throw new PidpServiceUnavailableException("Revocation lifecycle status request failed due to an unexpected error", e);
        }
    }
}
