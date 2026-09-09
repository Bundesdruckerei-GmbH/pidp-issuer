/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.port.out;

import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSessionView;
import de.bdr.pidp.issuer.authorization.core.domain.data.TokenIntrospectAuthSession;

public interface TokenIntrospectDataPortOut {
    TokenIntrospectAuthSession loadByAccessTokenID(String accessTokenID);
    void save(AuthSessionView authSessionView);
}
