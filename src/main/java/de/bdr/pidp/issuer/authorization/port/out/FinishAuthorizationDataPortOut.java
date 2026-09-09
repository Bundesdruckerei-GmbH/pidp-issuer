/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.port.out;

import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSessionView;
import de.bdr.pidp.issuer.authorization.core.domain.data.FinishAuthorizationAuthSession;

public interface FinishAuthorizationDataPortOut {
    FinishAuthorizationAuthSession loadByIssuerState(String issuerState);
    void save(AuthSessionView authSession);
}
