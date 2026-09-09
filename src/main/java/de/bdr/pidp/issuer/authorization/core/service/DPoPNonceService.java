/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.service;

import de.bdr.pidp.issuer.authorization.core.AuthorizationConfiguration;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSessionDPoPView;
import de.bdr.pidp.issuer.base.Nonce;
import de.bdr.pidp.issuer.base.NonceFactory;
import de.bdr.pidp.issuer.base.PidServerException;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Service;

import java.time.Duration;

@NullMarked
@Service
public class DPoPNonceService {
    private final Duration dpopNonceLifetime;

    public DPoPNonceService(AuthorizationConfiguration configuration) {
        this.dpopNonceLifetime = configuration.getPopNonceLifetime();
    }

    public Nonce provideAndSave(AuthSessionDPoPView authSessionDPoPView) {
        Nonce newDPoPNonce = NonceFactory.createSecureRandomNonce(dpopNonceLifetime);
        authSessionDPoPView.setDPoPNonce(newDPoPNonce);
        return newDPoPNonce;
    }

    /**
     * @throws PidServerException when no nonce or expiration time is found in the session
     */
    public Nonce fetchFromAuthSession(AuthSessionDPoPView session) {
        return new Nonce(session.getDpopNonce(), session.getDpopNonceExpirationTime());
    }
}
