/*
 * Copyright 2024-2026 Bundesdruckerei GmbH
 * For the license see the accompanying file LICENSE.MD.
 */
package de.bdr.pidp.issuer.authorization.adapter.out;

import de.bdr.pidp.issuer.authorization.core.domain.SeedCredential;
import de.bdr.pidp.issuer.authorization.port.out.IdentificationDataPortOut;
import de.bdr.pidp.issuer.authorization.port.out.IdentificationFailedException;
import de.bdr.pidp.issuer.authorization.port.out.InvalidSeedCredentialException;
import de.bdr.pidp.issuer.base.VerificationResult;
import de.bdr.pidp.issuer.identification.port.in.IdentificationDataPortIn;
import de.bdr.pidp.issuer.identification.port.in.ResourceDoesNotExistException;
import de.bdr.pidp.issuer.identification.port.in.SeedCredentialDTO;
import de.bdr.pidp.issuer.identification.port.in.SeedCredentialVerificationException;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

import java.net.URL;

@Component
@RequiredArgsConstructor
public class IdentificationDataAdapter implements IdentificationDataPortOut {

    private final IdentificationDataPortIn identificationProvider;

    @Override
    public URL startIdentificationProcess(URL redirectUrl, String issuerState, @Nullable String sessionId) {
        return identificationProvider.startIdentificationProcess(redirectUrl, issuerState, sessionId);
    }

    @Override
    public VerificationResult checkIdentification(String externalId) {
        try {
            return identificationProvider.checkIdentification(externalId);
        } catch (ResourceDoesNotExistException e) {
            throw new IdentificationFailedException("No identification result received yet", e);
        }
    }

    @Override
    public SeedCredential collectEncryptedIdentification(String externalId) {
        try {
            return map(identificationProvider.collectEncryptedIdentification(externalId));
        } catch (ResourceDoesNotExistException e) {
            throw new IdentificationFailedException(e.getMessage(), e);
        }
    }

    @Override
    public SeedCredential verifySeedCredential(String seedCredential) {
        try {
            return map(identificationProvider.verifySeedCredential(seedCredential));
        } catch (SeedCredentialVerificationException e) {
            throw new InvalidSeedCredentialException(e.getMessage(), e.getCause());
        }
    }

    private SeedCredential map(SeedCredentialDTO dto) {
        return new SeedCredential(dto.seedCredential(), dto.jti(), dto.sub(), dto.exp());
    }
}
