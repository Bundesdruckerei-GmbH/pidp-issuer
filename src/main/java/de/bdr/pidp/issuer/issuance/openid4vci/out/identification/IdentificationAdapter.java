/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.issuance.openid4vci.out.identification;

import de.bdr.pidp.issuer.base.identitydata.IdentityData;
import de.bdr.pidp.issuer.identification.port.in.IdentificationDataPortIn;
import de.bdr.pidp.issuer.identification.port.in.SeedCredentialVerificationException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class IdentificationAdapter {

    private final IdentificationDataPortIn identificationProvider;

    public IdentityData verifySeedCredentialAndGetIdentityData(String seedCredential) {
        try {
            return identificationProvider.verifySeedCredentialAndGetIdentitydata(seedCredential);
        } catch (SeedCredentialVerificationException e) {
            throw new InvalidSeedCredentialException(e.getMessage(), e.getCause());
        }
    }
}
