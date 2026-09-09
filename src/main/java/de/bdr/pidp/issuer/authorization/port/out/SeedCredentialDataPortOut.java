/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.port.out;

import de.bdr.pidp.issuer.authorization.core.domain.data.SeedCredentialDataAuthSession;

public interface SeedCredentialDataPortOut {
    SeedCredentialDataAuthSession loadBySeedCredentialRef(String seedCredentialRef);
}
