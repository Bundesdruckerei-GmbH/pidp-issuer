/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.port.out;

import com.nimbusds.jwt.SignedJWT;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSessionView;
import de.bdr.pidp.issuer.authorization.core.domain.data.RefreshTokenAuthSession;

public interface RefreshTokenDataPortOut {
    RefreshTokenAuthSession initByRefreshToken(SignedJWT refreshToken);
    RefreshTokenAuthSession loadByRefreshToken(SignedJWT refreshToken);
    void save(AuthSessionView authSessionView);
}
