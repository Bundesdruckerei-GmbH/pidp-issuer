/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.core.flows;

import de.bdr.pidp.issuer.authorization.core.domain.data.TokenIntrospectAuthSession;
import de.bdr.pidp.issuer.authorization.core.service.DPoPNonceService;
import de.bdr.pidp.issuer.authorization.in.TokenIntrospectPortIn;
import de.bdr.pidp.issuer.authorization.port.out.TokenIntrospectDataPortOut;
import de.bdr.pidp.issuer.base.Nonce;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
class TokenIntrospectService implements TokenIntrospectPortIn {

    private final TokenIntrospectDataPortOut tokenIntrospectDataPortOut;
    private final DPoPNonceService dPoPNonceService;

    @Override
    public Nonce getDPoPNonce(String accessTokenID) {
        TokenIntrospectAuthSession tokenIntrospectAuthSession = tokenIntrospectDataPortOut.loadByAccessTokenID(accessTokenID);
        return dPoPNonceService.fetchFromAuthSession(tokenIntrospectAuthSession);
    }

    @Override
    public Nonce provideAndStore(String accessTokenID) {
        TokenIntrospectAuthSession tokenIntrospectAuthSession = tokenIntrospectDataPortOut.loadByAccessTokenID(accessTokenID);
        try {
            return dPoPNonceService.provideAndSave(tokenIntrospectAuthSession);
        } finally {
            tokenIntrospectDataPortOut.save(tokenIntrospectAuthSession);
        }
    }
}
