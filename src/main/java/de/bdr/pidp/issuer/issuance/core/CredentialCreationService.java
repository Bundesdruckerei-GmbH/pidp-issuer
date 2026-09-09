/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.core;

import com.nimbusds.jose.jwk.JWK;
import de.bdr.pidp.issuer.base.identitydata.IdentityData;
import de.bdr.pidp.issuer.base.jwt.StatusListRef;
import de.bdr.pidp.issuer.issuance.config.IssuanceConfiguration;
import de.bdr.pidp.issuer.issuance.config.model.CredentialConfigurationID;
import de.bdr.pidp.issuer.issuance.core.service.CredentialCreator;
import de.bdr.pidp.issuer.issuance.core.service.PIDIdentityData;
import de.bdr.pidp.issuer.issuance.out.rs.PIDLifecycleAdapter;
import de.bdr.pidp.issuer.issuance.out.sls.StatusListAdapter;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

@NullMarked
@Service
@Slf4j
public class CredentialCreationService {

    private final StatusListAdapter statusListAdapter;
    private final Map<CredentialConfigurationID, CredentialCreator> credentialCreators;
    private final PIDLifecycleAdapter pidLifecycleAdapter;
    private final Duration lifetime;

    public CredentialCreationService(
        StatusListAdapter statusListAdapter,
        Map<CredentialConfigurationID, CredentialCreator> credentialCreators, PIDLifecycleAdapter pidLifecycleAdapter,
        IssuanceConfiguration issuanceConfiguration
    ) {
        this.statusListAdapter = statusListAdapter;
        this.credentialCreators = credentialCreators;
        this.pidLifecycleAdapter = pidLifecycleAdapter;
        this.lifetime = issuanceConfiguration.getLifetime();
    }

    public List<String> buildCredentials(List<JWK> holderBindingKeys, IdentityData identityData, CredentialConfigurationID credentialConfigurationID, String refreshTokenID) {
        var references = statusListAdapter.acquireFreeIndices(holderBindingKeys.size());
        var pidIdentityData = PIDIdentityData.fromIdentityData(identityData);
        var credentialCreator = getCredentialCreator(credentialConfigurationID);

        if (references.size() < holderBindingKeys.size()) {
            log.warn("Got less status references from status-list service than requested");
        }

        var validFrom =
            switch (credentialConfigurationID) {
                case SD_JWT_V1, MSO_MDOC_V1 -> Instant.now().truncatedTo(ChronoUnit.DAYS);
                default -> OffsetDateTime.now(CredentialCreator.localZoneId).truncatedTo(ChronoUnit.DAYS).toInstant();
            };
        var validUntil = validFrom.plus(lifetime);
        var validity = new CredentialCreator.Validity(validFrom, validUntil);

        int nrCredentials = Math.min(references.size(), holderBindingKeys.size());
        List<String> credentials = IntStream
            .range(0, nrCredentials)
            .mapToObj(i -> credentialCreator.create(pidIdentityData, holderBindingKeys.get(i), references.get(i), validity))
            .toList();

        List<StatusListRef> statusLists = IntStream
            .range(0, nrCredentials)
            .mapToObj(i -> new StatusListRef(references.get(i).uri(), references.get(i).index()))
            .toList();
        pidLifecycleAdapter.registerPIDs(refreshTokenID, validUntil, statusLists);

        return credentials;
    }

    private CredentialCreator getCredentialCreator(CredentialConfigurationID credentialConfigurationID) {
        var credentialCreator = credentialCreators.get(credentialConfigurationID);

        if (credentialCreator == null) {
            throw new IllegalStateException("Credential creator not found for credential id " + credentialConfigurationID);
        }
        return credentialCreator;
    }

}
