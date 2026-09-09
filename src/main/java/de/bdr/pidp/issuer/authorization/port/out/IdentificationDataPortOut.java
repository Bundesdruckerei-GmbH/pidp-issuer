/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.port.out;

import de.bdr.pidp.issuer.authorization.core.domain.SeedCredential;
import de.bdr.pidp.issuer.base.VerificationResult;
import org.jspecify.annotations.Nullable;

import java.net.URL;

public interface IdentificationDataPortOut {
    URL startIdentificationProcess(URL redirectUrl, String issuerState, @Nullable String sessionId);

    /**
     * @throws IdentificationFailedException when no eID result is found
     */
    VerificationResult checkIdentification(String externalId);

    /**
     * @throws IdentificationFailedException when no eID result is found
     */
    SeedCredential collectEncryptedIdentification(String externalId);

    SeedCredential verifySeedCredential(String seedCredential);
}
