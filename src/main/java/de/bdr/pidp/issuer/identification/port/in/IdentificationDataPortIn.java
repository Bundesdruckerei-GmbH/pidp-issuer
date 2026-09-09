/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.identification.port.in;

import de.bdr.pidp.issuer.base.VerificationResult;
import de.bdr.pidp.issuer.base.identitydata.IdentityData;
import org.jspecify.annotations.Nullable;

import java.net.URL;

public interface IdentificationDataPortIn {
    URL startIdentificationProcess(URL redirectUrl, String issuerState, @Nullable String sessionId);

    /**
     * @throws ResourceDoesNotExistException when no eID result is found
     */
    VerificationResult checkIdentification(String externalId);

    /**
     * @throws ResourceDoesNotExistException when no eID result is found
     */
    SeedCredentialDTO collectEncryptedIdentification(String externalId);

    /**
     * @throws SeedCredentialVerificationException when verification failed or identity data not eligible
     */
    SeedCredentialDTO verifySeedCredential(String seedCredential);

    /**
     * @throws SeedCredentialVerificationException when verification failed or identity data not eligible
     */
    IdentityData verifySeedCredentialAndGetIdentitydata(String seedCredential);
}
