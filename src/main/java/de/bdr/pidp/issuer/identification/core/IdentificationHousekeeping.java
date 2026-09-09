/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.core;

import de.bdr.pidp.issuer.identification.core.model.AuthenticationState;
import de.bdr.pidp.issuer.identification.out.persistence.EIDResultAdapter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

@Slf4j
@Service
public class IdentificationHousekeeping {
    private final AuthenticationStore authenticationStore;
    private final EIDResultAdapter eidResultAdapter;

    public IdentificationHousekeeping(AuthenticationStore authenticationStore, EIDResultAdapter eidResultAdapter) {
        this.authenticationStore = authenticationStore;
        this.eidResultAdapter = eidResultAdapter;
    }

    public void cleanupExpiredAuthentications() {
        authenticationStore.updateStateByValidUntilBeforeAndAuthenticationStateNotIn(AuthenticationState.TIMEOUT, Instant.now(), List.of(AuthenticationState.TERMINATED, AuthenticationState.TIMEOUT));
        var count = authenticationStore.deleteByAuthenticationStateIn(List.of(AuthenticationState.TERMINATED, AuthenticationState.TIMEOUT));
        log.info("Deleted {} terminated or expired authentications", count);

        var resultCount = eidResultAdapter.deleteExpired();
        log.info("Deleted {} expired eID results", resultCount);
    }
}
