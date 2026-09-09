/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.port.out;

import de.bdr.pidp.issuer.authorization.core.domain.data.AuthSessionView;
import de.bdr.pidp.issuer.authorization.core.domain.data.AuthorizeAuthSession;

public interface AuthorizeDataPortOut {
    AuthorizeAuthSession loadByRequestUri(String requestUri);
    void save(AuthSessionView authSession);
}
