/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.out.authorization;

import de.bdr.pidp.issuer.authorization.in.SeedCredentialDataPortIn;
import de.bdr.pidp.issuer.authorization.in.TokenIntrospectPortIn;
import de.bdr.pidp.issuer.base.Nonce;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthorizationAdapter {
    private final TokenIntrospectPortIn tokenIntrospectPortIn;
    private final SeedCredentialDataPortIn seedCredentialDataPortIn;

    public String retrieveSeedCredential(String seedCredentialRef) {
        return seedCredentialDataPortIn.retrieveSeedCredentialData(seedCredentialRef);
    }

    public Nonce getDPoPNonce(String accessTokenID) {
        return tokenIntrospectPortIn.getDPoPNonce(accessTokenID);
    }

    public Nonce provideAndStore(String accessTokenID) {
        return tokenIntrospectPortIn.provideAndStore(accessTokenID);
    }
}
